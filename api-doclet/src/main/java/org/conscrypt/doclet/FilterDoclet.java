/*
 * Copyright (C) 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Originally from Doclava project at
 * https://android.googlesource.com/platform/external/doclava/+/master/src/com/google/doclava/Doclava.java
 */

package org.conscrypt.doclet;

import com.sun.javadoc.*;
import com.sun.tools.doclets.standard.Standard;
import com.sun.tools.javadoc.Main;
import java.io.FileNotFoundException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

/**
 * This Doclet filters out all classes, methods, fields, etc. that have the {@code @Internal}
 * annotation on them.
 */
public class FilterDoclet extends com.sun.tools.doclets.standard.Standard {
    public static void main(String[] args) throws FileNotFoundException {
        String name = FilterDoclet.class.getName();
        Main.execute(name, args);
    }

    public static boolean start(RootDoc rootDoc) {
        return Standard.start((RootDoc) filterHidden(rootDoc, RootDoc.class));
    }

    /**
     * Returns true if the given element has an @Internal annotation.
     */
    private static boolean hasHideAnnotation(ProgramElementDoc doc) {
        for (AnnotationDesc ann : doc.annotations()) {
            if (ann.annotationType().qualifiedTypeName().equals("org.conscrypt.Internal")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns true if the given element is hidden.
     */
    private static boolean isHidden(Doc doc) {
        // Methods, fields, constructors.
        if (doc instanceof MemberDoc) {
            return hasHideAnnotation((MemberDoc) doc);
        }
        // Classes, interfaces, enums, annotation types.
        if (doc instanceof ClassDoc) {
            // Check the class doc and containing class docs if this is a
            // nested class.
            ClassDoc current = (ClassDoc) doc;
            do {
                if (hasHideAnnotation(current)) {
                    return true;
                }
                current = current.containingClass();
            } while (current != null);
        }
        return false;
    }

    /**
     * Filters out hidden elements.
     */
    private static Object filterHidden(Object o, Class<?> expected) {
        if (o == null) {
            return null;
        }

        Class<?> type = o.getClass();
        if (type.getName().startsWith("com.sun.")) {
            // TODO: Implement interfaces from superclasses, too.
            return Proxy.newProxyInstance(
                    type.getClassLoader(), type.getInterfaces(), new HideHandler(o));
        } else if (o instanceof Object[]) {
            Class<?> componentType = expected.getComponentType();
            if (componentType == null) {
                return o;
            }

            Object[] array = (Object[]) o;
            List<Object> list = new ArrayList<Object>(array.length);
            for (Object entry : array) {
                if ((entry instanceof Doc) && isHidden((Doc) entry)) {
                    continue;
                }
                list.add(filterHidden(entry, componentType));
            }
            return list.toArray((Object[]) Array.newInstance(componentType, list.size()));
        } else {
            return o;
        }
    }

    /**
     * Filters hidden elements.
     */
    private static class HideHandler implements InvocationHandler {
        private final Object target;

        public HideHandler(Object target) {
            this.target = target;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String methodName = method.getName();
            if (args != null) {
                if (methodName.equals("compareTo") || methodName.equals("equals")
                        || methodName.equals("overrides") || methodName.equals("subclassOf")) {
                    args[0] = unwrap(args[0]);
                }
            }

            try {
                return filterHidden(method.invoke(target, args), method.getReturnType());
            } catch (InvocationTargetException e) {
                e.printStackTrace();
                throw e.getTargetException();
            }
        }

        private static Object unwrap(Object proxy) {
            if (proxy instanceof Proxy)
                return ((HideHandler) Proxy.getInvocationHandler(proxy)).target;
            return proxy;
        }
    }
}
