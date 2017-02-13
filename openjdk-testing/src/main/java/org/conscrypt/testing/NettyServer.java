/*
 * Copyright 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.conscrypt.testing;

import static io.netty.channel.ChannelOption.SO_BACKLOG;
import static io.netty.channel.ChannelOption.SO_KEEPALIVE;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLEngine;

/**
 * A test server based on Netty and Netty-tcnative.
 */
public final class NettyServer {
    private final int port;
    private final int messageSize;
    private EventLoopGroup group;
    private Channel channel;
    private String cipher;
    private volatile MessageProcessor messageProcessor = new BatchMessageProcessor(1);

    /**
     * A processor for receipt of a single message.
     */
    public interface MessageProcessor {
        void processMessage(ChannelHandlerContext ctx, ByteBuf request);
    }

    /**
     * A {@link MessageProcessor} that waits for receipt of a number of messages in a
     * batch before replying with the last received message.
     */
    static final class BatchMessageProcessor implements MessageProcessor {
        private final int batchSize;
        private int messageCount;

        BatchMessageProcessor(int batchSize) {
            this.batchSize = batchSize;
        }

        @Override
        public void processMessage(ChannelHandlerContext ctx, ByteBuf request) {
            if (messageCount == batchSize - 1) {
                ctx.writeAndFlush(request);
            }
            messageCount = (messageCount + 1) % batchSize;
        }
    }

    public NettyServer(int port, int messageSize, String cipher) {
        this.port = port;
        this.messageSize = messageSize;
        this.cipher = cipher;
    }

    public void setMessageProcessor(MessageProcessor messageProcessor) {
        this.messageProcessor = messageProcessor;
    }

    public void start() {
        group = new NioEventLoopGroup();
        ServerBootstrap b = new ServerBootstrap();
        b.group(group);
        b.channel(NioServerSocketChannel.class);
        b.option(SO_BACKLOG, 128);
        b.childOption(SO_KEEPALIVE, true);
        b.childHandler(new ChannelInitializer<Channel>() {
            @Override
            public void initChannel(final Channel ch) throws Exception {
                SslContext context = TestUtil.newNettyServerContext(cipher);
                SSLEngine sslEngine = context.newEngine(ch.alloc());
                ch.pipeline().addFirst(new SslHandler(sslEngine));
                ch.pipeline().addLast(new MessageDecoder());
            }
        });
        // Bind and start to accept incoming connections.
        ChannelFuture future = b.bind(port);
        try {
            future.await();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted waiting for bind");
        }
        if (!future.isSuccess()) {
            throw new RuntimeException("Failed to bind", future.cause());
        }
        channel = future.channel();
    }

    public void stop() {
        if (channel != null) {
            channel.close().awaitUninterruptibly();
        }
        if (group != null) {
            try {
                // Wait for the shutdown to complete.
                group.shutdownGracefully(1, 5, TimeUnit.SECONDS).get();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Handler that automatically responds with ever message it receives.
     */
    private final class MessageDecoder extends ByteToMessageDecoder {
        @Override
        protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out)
                throws Exception {
            if (in.readableBytes() >= messageSize) {
                messageProcessor.processMessage(ctx, in.readSlice(messageSize));
            }
        }
    }
}
