package org.conscrypt;

import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;


/**
 * Test support class for filtering collections of {@link Method}.  Each filter is a list of
 * predicates which must all be true for a Method in order for it to be included it the output.
 */
public class MethodFilter {
    private final String name;
    private final CompoundMethodPredicate predicates = new CompoundMethodPredicate();
    private int expectedSize = 0;

    public MethodFilter(String name) {
        this.name = name;
    }

    public List<Method> filter(Iterable<Method> input) {
        List<Method> result = new ArrayList<>();
        for (Method method : input) {
            if (predicates.test(method)) {
                result.add(method);
            }
        }
        if (expectedSize != 0) {
            assertTrue(String.format("Filter %s only returned %d methods, expected at least %d",
                    name, result.size(), expectedSize), result.size() >= expectedSize);
        }
        return result;
    }

    /** Returns a new {@link Builder} */
    public static Builder newBuilder(String name) {
        return new Builder(name);
    }

    /** Returns a filter which selects only methods named in {@code methodNames} */
    public static MethodFilter nameFilter(String name, String... methodNames) {
        return newBuilder(name)
                .named(methodNames)
                .expectSize(methodNames.length)
                .build();
    }

    private void addPredicate(Predicate<Method> predicate) {
        predicates.add(predicate);
    }

    public static class Builder {
        private final MethodFilter filter;

        private Builder(String name) {
            filter = new MethodFilter(name);
        }

        /** Method's simple name must start with {@code prefix}.  */
        public Builder hasPrefix(String prefix) {
            filter.addPredicate(new MethodNamePrefixPredicate(prefix));
            return this;
        }

        /** Argument at {@code position} must be one of the supplied {@code classes}. */
        public Builder hasArg(int position, Class<?>... classes) {
            filter.addPredicate(new MethodArgPredicate(position, classes));
            return this;
        }

        /** Method must take exactly {@code length} args. */
        public Builder hasArgLength(int length) {
            filter.addPredicate(new MethodArgLengthPredicate(length));
            return this;
        }

        /* Method must take one or more arguments, i.e. not void. */
        public Builder takesArguments() {
            filter.addPredicate(new MethodArgLengthPredicate(0).negate());
            return this;
        }

        /** Method's simple name is in the list of {@code names} provided. */
        public Builder named(String... names) {
            filter.addPredicate(new MethodNamePredicate(names));
            return this;
        }

        /** Method's simple name is NOT in the list of {@code names} provided. */
        public Builder except(String... names) {
            filter.addPredicate(new MethodNamePredicate(names).negate());
            return this;
        }

        /** Expect at least {@code size} matching methods when filtering, otherwise filter()
         * will throw {@code AssertionError} */
        public Builder expectSize(int size) {
            filter.expectedSize = size;
            return this;
        }

        public MethodFilter build() {
            return filter;
        }
    }

    // Implements Builder.hasPrefix()
    private static class MethodNamePrefixPredicate implements Predicate<Method> {
        private final String prefix;

        public MethodNamePrefixPredicate(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public boolean test(Method method) {
            return method.getName().startsWith(prefix);
        }
    }

    // Implements Builder.named()
    private static class MethodNamePredicate implements Predicate<Method> {
        private final List<String> names;

        public MethodNamePredicate(String... names) {
            this.names = Arrays.asList(names);
        }

        @Override
        public boolean test(Method method) {
            return names.contains(method.getName());
        }
    }

    // Implements Builder.hasArg()
    private static class MethodArgPredicate implements Predicate<Method> {
        private final int position;
        private final List<Class<?>> allowedClasses;

        public MethodArgPredicate(int position, Class<?>... classes) {
            this.position = position;
            allowedClasses = Arrays.asList(classes);
        }

        @Override
        public boolean test(Method method) {
            Class<?>[] argTypes = method.getParameterTypes();
            if (argTypes.length > position) {
                for (Class<?> c : allowedClasses) {
                    if (argTypes[position] == c) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    // Implements Builder.hasArgLength()
    private static class MethodArgLengthPredicate implements Predicate<Method> {
        private final int length;

        public MethodArgLengthPredicate(int length) {
            this.length = length;
        }

        @Override
        public boolean test(Method method) {
            return method.getParameterCount() == length;
        }
    }

    // A Predicate which contains a list of sub-Predicates, all of which must be true
    // for this one to be true.
    private static class CompoundMethodPredicate implements Predicate<Method> {
        private final List<Predicate<Method>> predicates = new ArrayList<>();

        @Override
        public boolean test(Method method) {
            for (Predicate<Method> p : predicates) {
                if (!p.test(method)) {
                    return false;
                }
            }
            return true;
        }

        public void add(Predicate<Method> predicate) {
            predicates.add(predicate);
        }
    }
}