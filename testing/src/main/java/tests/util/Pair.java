/*
 * Copyright (C) 2010 The Android Open Source Project
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
package tests.util;
/**
 * Pair of typed values.
 *
 * <p>Pairs are obtained using {@link #of(Object, Object) of}.
 *
 * @param <F> type of the first value.
 * @param <S> type of the second value.
 */
public class Pair<F, S> {
    private final F mFirst;
    private final S mSecond;
    private Pair(F first, S second) {
        mFirst = first;
        mSecond = second;
    }
    /**
     * Gets the pair consisting of the two provided values.
     *
     * @param first first value or {@code null}.
     * @param second second value or {@code null}.
     */
    public static <F, S> Pair<F, S> of(F first, S second) {
        return new Pair<F, S>(first, second);
    }
    /**
     * Gets the first value from this pair.
     *
     * @return value or {@code null}.
     */
    public F getFirst() {
        return mFirst;
    }
    /**
     * Gets the second value from this pair.
     *
     * @return value or {@code null}.
     */
    public S getSecond() {
        return mSecond;
    }
    @Override
    public String toString() {
        return "Pair[" + mFirst + ", " + mSecond + "]";
    }
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mFirst == null) ? 0 : mFirst.hashCode());
        result = prime * result + ((mSecond == null) ? 0 : mSecond.hashCode());
        return result;
    }
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof Pair)) {
            return false;
        }
        @SuppressWarnings("rawtypes")
        Pair other = (Pair) obj;
        if (mFirst == null) {
            if (other.mFirst != null) {
                return false;
            }
        } else if (!mFirst.equals(other.mFirst)) {
            return false;
        }
        if (mSecond == null) {
            if (other.mSecond != null) {
                return false;
            }
        } else if (!mSecond.equals(other.mSecond)) {
            return false;
        }
        return true;
    }
}
