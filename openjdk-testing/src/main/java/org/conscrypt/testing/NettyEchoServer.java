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
import org.conscrypt.testing.TestUtil;

/**
 * A test server based on Netty and Netty-tcnative that auto-replies with every message
 * it receives.
 */
public final class NettyEchoServer {
    private final EventLoopGroup group = new NioEventLoopGroup();
    private final int port;
    private final int messageSize;
    private Channel channel;
    private String cipher;

    public NettyEchoServer(int port, int messageSize, String cipher) {
        this.port = port;
        this.messageSize = messageSize;
        this.cipher = cipher;
    }

    public void start() {
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
                ch.pipeline().addLast(new EchoService());
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
            group.shutdownGracefully(1, 5, TimeUnit.SECONDS);
        }
    }

    /**
     * Handler that automatically responds with ever message it receives.
     */
    private final class EchoService extends ByteToMessageDecoder {
        @Override
        protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out)
                throws Exception {
            if (in.readableBytes() >= messageSize) {
                // Copy the input to a new direct buffer.
                ByteBuf response = ctx.alloc().directBuffer(messageSize);
                response.writeBytes(in, in.readerIndex(), messageSize);
                in.skipBytes(messageSize);

                ctx.writeAndFlush(response);
            }
        }
    }
}
