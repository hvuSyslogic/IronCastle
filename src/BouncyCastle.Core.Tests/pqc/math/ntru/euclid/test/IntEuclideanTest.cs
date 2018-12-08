﻿/// <summary>
/// Copyright (c) 2011 Tim Buktu (tbuktu@hotmail.com)
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a
/// copy of this software and associated documentation files (the "Software"),
/// to deal in the Software without restriction, including without limitation
/// the rights to use, copy, modify, merge, publish, distribute, sublicense,
/// and/or sell copies of the Software, and to permit persons to whom the
/// Software is furnished to do so, subject to the following conditions:
/// 
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
/// 
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
/// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
/// DEALINGS IN THE SOFTWARE.
/// </summary>

namespace org.bouncycastle.pqc.math.ntru.euclid.test
{
	using TestCase = junit.framework.TestCase;

	public class IntEuclideanTest : TestCase
	{
		public virtual void testCalculate()
		{
			IntEuclidean r = IntEuclidean.calculate(120, 23);
			assertEquals(-9, r.x);
			assertEquals(47, r.y);
			assertEquals(1, r.gcd);

			r = IntEuclidean.calculate(126, 231);
			assertEquals(2, r.x);
			assertEquals(-1, r.y);
			assertEquals(21, r.gcd);
		}
	}
}