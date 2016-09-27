/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef _CONSCRYPT_UNUSED_H
#define _CONSCRYPT_UNUSED_H

#define UNUSED_1(a) ((void)(a))
#define UNUSED_2(a,b) ((void)(a)),UNUSED_1(b)
#define UNUSED_3(a,b,c) ((void)(a)),UNUSED_2(b,c)
#define UNUSED_4(a,b,c,d) ((void)(a)),UNUSED_3(b,c,d)
#define UNUSED_5(a,b,c,d,e) ((void)(a)),UNUSED_4(b,c,d,e)
#define UNUSED_6(a,b,c,d,e,f) ((void)(a)),UNUSED_5(b,c,d,e,f)
#define UNUSED_7(a,b,c,d,e,f,g) ((void)(a)),UNUSED_6(b,c,d,e,f,g)
#define UNUSED_8(a,b,c,d,e,f,g,h) ((void)(a)),UNUSED_7(b,c,d,e,f,g,h)
#define UNUSED_9(a,b,c,d,e,f,g,h,i) ((void)(a)),UNUSED_8(b,c,d,e,f,g,h,i)
#define UNUSED_10(a,b,c,d,e,f,g,h,i,j) ((void)(a)),UNUSED_9(b,c,d,e,f,g,h,i,j)
#define UNUSED_11(a,b,c,d,e,f,g,h,i,j,k) ((void)(a)),UNUSED_10(b,c,d,e,f,g,h,i,j,k)
#define UNUSED_12(a,b,c,d,e,f,g,h,i,j,k,l) ((void)(a)),UNUSED_11(b,c,d,e,f,g,h,i,j,k,l)
#define UNUSED_13(a,b,c,d,e,f,g,h,i,j,k,l,m) ((void)(a)),UNUSED_12(b,c,d,e,f,g,h,i,j,k,l,m)
#define UNUSED_14(a,b,c,d,e,f,g,h,i,j,k,l,m,n) ((void)(a)),UNUSED_13(b,c,d,e,f,g,h,i,j,k,l,m,n)

#define VA_ARGS_UNUSED_IMPL_(num) UNUSED_ ## num
#define VA_ARGS_UNUSED_IMPL(num) VA_ARGS_UNUSED_IMPL_(num)

#define VA_NARGS_IMPL(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,N,...) N
#define VA_NARGS(...) VA_NARGS_IMPL(__VA_ARGS__,14,13,12,11,10,9,8,7,6,5,4,3,2,1)

#define VA_ARGS_UNUSED(...) VA_ARGS_UNUSED_IMPL( VA_NARGS(__VA_ARGS__))(__VA_ARGS__ )

#endif /* _CONSCRYPT_UNUSED_H */
