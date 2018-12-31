using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.math.linearalgebra
{



	/// <summary>
	/// This class implements elements of finite binary fields <i>GF(2<sup>n</sup>)</i>
	/// using polynomial representation. For more information on the arithmetic see
	/// for example IEEE Standard 1363 or <a
	/// href=http://www.certicom.com/research/online.html> Certicom online-tutorial</a>.
	/// </summary>
	/// <seealso cref= "GF2nField" </seealso>
	/// <seealso cref= GF2nPolynomialField </seealso>
	/// <seealso cref= GF2nONBElement </seealso>
	/// <seealso cref= GF2Polynomial </seealso>
	public class GF2nPolynomialElement : GF2nElement
	{

		// pre-computed Bitmask for fast masking, bitMask[a]=0x1 << a
		private static readonly int[] bitMask = new int[] {0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00002000, 0x00004000, 0x00008000, 0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000, 0x00800000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, unchecked((int)0x80000000), 0x00000000};

		// the used GF2Polynomial which stores the coefficients
		private GF2Polynomial polynomial;

		/// <summary>
		/// Create a new random GF2nPolynomialElement using the given field and
		/// source of randomness.
		/// </summary>
		/// <param name="f">    the GF2nField to use </param>
		/// <param name="rand"> the source of randomness </param>
		public GF2nPolynomialElement(GF2nPolynomialField f, Random rand)
		{
			mField = f;
			mDegree = mField.getDegree();
			polynomial = new GF2Polynomial(mDegree);
			randomize(rand);
		}

		/// <summary>
		/// Creates a new GF2nPolynomialElement using the given field and Bitstring.
		/// </summary>
		/// <param name="f">  the GF2nPolynomialField to use </param>
		/// <param name="bs"> the desired value as Bitstring </param>
		public GF2nPolynomialElement(GF2nPolynomialField f, GF2Polynomial bs)
		{
			mField = f;
			mDegree = mField.getDegree();
			polynomial = new GF2Polynomial(bs);
			polynomial.expandN(mDegree);
		}

		/// <summary>
		/// Creates a new GF2nPolynomialElement using the given field <i>f</i> and
		/// byte[] <i>os</i> as value. The conversion is done according to 1363.
		/// </summary>
		/// <param name="f">  the GF2nField to use </param>
		/// <param name="os"> the octet string to assign to this GF2nPolynomialElement </param>
		/// <seealso cref= "P1363 5.5.5 p23, OS2FEP/OS2BSP" </seealso>
		public GF2nPolynomialElement(GF2nPolynomialField f, byte[] os)
		{
			mField = f;
			mDegree = mField.getDegree();
			polynomial = new GF2Polynomial(mDegree, os);
			polynomial.expandN(mDegree);
		}

		/// <summary>
		/// Creates a new GF2nPolynomialElement using the given field <i>f</i> and
		/// int[] <i>is</i> as value.
		/// </summary>
		/// <param name="f">  the GF2nField to use </param>
		/// <param name="is"> the integer string to assign to this GF2nPolynomialElement </param>
		public GF2nPolynomialElement(GF2nPolynomialField f, int[] @is)
		{
			mField = f;
			mDegree = mField.getDegree();
			polynomial = new GF2Polynomial(mDegree, @is);
			polynomial.expandN(f.mDegree);
		}

		/// <summary>
		/// Creates a new GF2nPolynomialElement by cloning the given
		/// GF2nPolynomialElement <i>b</i>.
		/// </summary>
		/// <param name="other"> the GF2nPolynomialElement to clone </param>
		public GF2nPolynomialElement(GF2nPolynomialElement other)
		{
			mField = other.mField;
			mDegree = other.mDegree;
			polynomial = new GF2Polynomial(other.polynomial);
		}

		// /////////////////////////////////////////////////////////////////////
		// pseudo-constructors
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		/// Creates a new GF2nPolynomialElement by cloning this
		/// GF2nPolynomialElement.
		/// </summary>
		/// <returns> a copy of this element </returns>
		public override object clone()
		{
			return new GF2nPolynomialElement(this);
		}

		// /////////////////////////////////////////////////////////////////////
		// assignments
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		/// Assigns the value 'zero' to this Polynomial.
		/// </summary>
		public override void assignZero()
		{
			polynomial.assignZero();
		}

		/// <summary>
		/// Create the zero element.
		/// </summary>
		/// <param name="f"> the finite field </param>
		/// <returns> the zero element in the given finite field </returns>
		public static GF2nPolynomialElement ZERO(GF2nPolynomialField f)
		{
			GF2Polynomial polynomial = new GF2Polynomial(f.getDegree());
			return new GF2nPolynomialElement(f, polynomial);
		}

		/// <summary>
		/// Create the one element.
		/// </summary>
		/// <param name="f"> the finite field </param>
		/// <returns> the one element in the given finite field </returns>
		public static GF2nPolynomialElement ONE(GF2nPolynomialField f)
		{
			GF2Polynomial polynomial = new GF2Polynomial(f.getDegree(), new int[]{1});
			return new GF2nPolynomialElement(f, polynomial);
		}

		/// <summary>
		/// Assigns the value 'one' to this Polynomial.
		/// </summary>
		public override void assignOne()
		{
			polynomial.assignOne();
		}

		/// <summary>
		/// Assign a random value to this GF2nPolynomialElement using the specified
		/// source of randomness.
		/// </summary>
		/// <param name="rand"> the source of randomness </param>
		private void randomize(Random rand)
		{
			polynomial.expandN(mDegree);
			polynomial.randomize(rand);
		}

		// /////////////////////////////////////////////////////////////////////
		// comparison
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		/// Checks whether this element is zero.
		/// </summary>
		/// <returns> <tt>true</tt> if <tt>this</tt> is the zero element </returns>
		public override bool isZero()
		{
			return polynomial.isZero();
		}

		/// <summary>
		/// Tests if the GF2nPolynomialElement has 'one' as value.
		/// </summary>
		/// <returns> true if <i>this</i> equals one (this == 1) </returns>
		public override bool isOne()
		{
			return polynomial.isOne();
		}

		/// <summary>
		/// Compare this element with another object.
		/// </summary>
		/// <param name="other"> the other object </param>
		/// <returns> <tt>true</tt> if the two objects are equal, <tt>false</tt>
		///         otherwise </returns>
		public override bool Equals(object other)
		{
			if (other == null || !(other is GF2nPolynomialElement))
			{
				return false;
			}
			GF2nPolynomialElement otherElem = (GF2nPolynomialElement)other;

			if (mField != otherElem.mField)
			{
				if (!mField.getFieldPolynomial().Equals(otherElem.mField.getFieldPolynomial()))
				{
					return false;
				}
			}

			return polynomial.Equals(otherElem.polynomial);
		}

		/// <returns> the hash code of this element </returns>
		public override int GetHashCode()
		{
			return mField.GetHashCode() + polynomial.GetHashCode();
		}

		// /////////////////////////////////////////////////////////////////////
		// access
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		/// Returns the value of this GF2nPolynomialElement in a new Bitstring.
		/// </summary>
		/// <returns> the value of this GF2nPolynomialElement in a new Bitstring </returns>
		private GF2Polynomial getGF2Polynomial()
		{
			return new GF2Polynomial(polynomial);
		}

		/// <summary>
		/// Checks whether the indexed bit of the bit representation is set.
		/// </summary>
		/// <param name="index"> the index of the bit to test </param>
		/// <returns> <tt>true</tt> if the indexed bit is set </returns>
		public override bool testBit(int index)
		{
			return polynomial.testBit(index);
		}

		/// <summary>
		/// Returns whether the rightmost bit of the bit representation is set. This
		/// is needed for data conversion according to 1363.
		/// </summary>
		/// <returns> true if the rightmost bit of this element is set </returns>
		public override bool testRightmostBit()
		{
			return polynomial.testBit(0);
		}

		/// <summary>
		/// Compute the sum of this element and <tt>addend</tt>.
		/// </summary>
		/// <param name="addend"> the addend </param>
		/// <returns> <tt>this + other</tt> (newly created) </returns>
		public override GFElement add(GFElement addend)
		{
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.addToThis(addend);
			return result;
		}

		/// <summary>
		/// Compute <tt>this + addend</tt> (overwrite <tt>this</tt>).
		/// </summary>
		/// <param name="addend"> the addend </param>
		public override void addToThis(GFElement addend)
		{
			if (!(addend is GF2nPolynomialElement))
			{
				throw new RuntimeException();
			}
			if (!mField.Equals(((GF2nPolynomialElement)addend).mField))
			{
				throw new RuntimeException();
			}
			polynomial.addToThis(((GF2nPolynomialElement)addend).polynomial);
		}

		/// <summary>
		/// Returns <tt>this</tt> element + 'one".
		/// </summary>
		/// <returns> <tt>this</tt> + 'one' </returns>
		public override GF2nElement increase()
		{
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.increaseThis();
			return result;
		}

		/// <summary>
		/// Increases this element by 'one'.
		/// </summary>
		public override void increaseThis()
		{
			polynomial.increaseThis();
		}

		/// <summary>
		/// Compute the product of this element and <tt>factor</tt>.
		/// </summary>
		/// <param name="factor"> the factor </param>
		/// <returns> <tt>this * factor</tt> (newly created) </returns>
		public override GFElement multiply(GFElement factor)
		{
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.multiplyThisBy(factor);
			return result;
		}

		/// <summary>
		/// Compute <tt>this * factor</tt> (overwrite <tt>this</tt>).
		/// </summary>
		/// <param name="factor"> the factor </param>
		public override void multiplyThisBy(GFElement factor)
		{
			if (!(factor is GF2nPolynomialElement))
			{
				throw new RuntimeException();
			}
			if (!mField.Equals(((GF2nPolynomialElement)factor).mField))
			{
				throw new RuntimeException();
			}
			if (Equals(factor))
			{
				squareThis();
				return;
			}
			polynomial = polynomial.multiply(((GF2nPolynomialElement)factor).polynomial);
			reduceThis();
		}

		/// <summary>
		/// Compute the multiplicative inverse of this element.
		/// </summary>
		/// <returns> <tt>this<sup>-1</sup></tt> (newly created) </returns>
		/// <exception cref="System.ArithmeticException"> if <tt>this</tt> is the zero element. </exception>
		/// <seealso cref= GF2nPolynomialElement#invertMAIA </seealso>
		/// <seealso cref= GF2nPolynomialElement#invertEEA </seealso>
		/// <seealso cref= GF2nPolynomialElement#invertSquare </seealso>
		public override GFElement invert()
		{
			return invertMAIA();
		}

		/// <summary>
		/// Calculates the multiplicative inverse of <i>this</i> and returns the
		/// result in a new GF2nPolynomialElement.
		/// </summary>
		/// <returns> <i>this</i>^(-1) </returns>
		/// <exception cref="System.ArithmeticException"> if <i>this</i> equals zero </exception>
		public virtual GF2nPolynomialElement invertEEA()
		{
			if (isZero())
			{
				throw new ArithmeticException();
			}
			GF2Polynomial b = new GF2Polynomial(mDegree + 32, "ONE");
			b.reduceN();
			GF2Polynomial c = new GF2Polynomial(mDegree + 32);
			c.reduceN();
			GF2Polynomial u = getGF2Polynomial();
			GF2Polynomial v = mField.getFieldPolynomial();
			GF2Polynomial h;
			int j;
			u.reduceN();
			while (!u.isOne())
			{
				u.reduceN();
				v.reduceN();
				j = u.getLength() - v.getLength();
				if (j < 0)
				{
					h = u;
					u = v;
					v = h;
					h = b;
					b = c;
					c = h;
					j = -j;
					c.reduceN(); // this increases the performance
				}
				u.shiftLeftAddThis(v, j);
				b.shiftLeftAddThis(c, j);
			}
			b.reduceN();
			return new GF2nPolynomialElement((GF2nPolynomialField)mField, b);
		}

		/// <summary>
		/// Calculates the multiplicative inverse of <i>this</i> and returns the
		/// result in a new GF2nPolynomialElement.
		/// </summary>
		/// <returns> <i>this</i>^(-1) </returns>
		/// <exception cref="ArithmeticException"> if <i>this</i> equals zero </exception>
		public virtual GF2nPolynomialElement invertSquare()
		{
			GF2nPolynomialElement n;
			GF2nPolynomialElement u;
			int i, j, k, b;

			if (isZero())
			{
				throw new ArithmeticException();
			}
			// b = (n-1)
			b = mField.getDegree() - 1;
			// n = a
			n = new GF2nPolynomialElement(this);
			n.polynomial.expandN((mDegree << 1) + 32); // increase performance
			n.polynomial.reduceN();
			// k = 1
			k = 1;

			// for i = (r-1) downto 0 do, r=bitlength(b)
			for (i = IntegerFunctions.floorLog(b) - 1; i >= 0; i--)
			{
				// u = n
				u = new GF2nPolynomialElement(n);
				// for j = 1 to k do
				for (j = 1; j <= k; j++)
				{
					// u = u^2
					u.squareThisPreCalc();
				}
				// n = nu
				n.multiplyThisBy(u);
				// k = 2k
				k <<= 1;
				// if b(i)==1
				if ((b & bitMask[i]) != 0)
				{
					// n = n^2 * b
					n.squareThisPreCalc();
					n.multiplyThisBy(this);
					// k = k+1
					k += 1;
				}
			}

			// outpur n^2
			n.squareThisPreCalc();
			return n;
		}

		/// <summary>
		/// Calculates the multiplicative inverse of <i>this</i> using the modified
		/// almost inverse algorithm and returns the result in a new
		/// GF2nPolynomialElement.
		/// </summary>
		/// <returns> <i>this</i>^(-1) </returns>
		/// <exception cref="ArithmeticException"> if <i>this</i> equals zero </exception>
		public virtual GF2nPolynomialElement invertMAIA()
		{
			if (isZero())
			{
				throw new ArithmeticException();
			}
			GF2Polynomial b = new GF2Polynomial(mDegree, "ONE");
			GF2Polynomial c = new GF2Polynomial(mDegree);
			GF2Polynomial u = getGF2Polynomial();
			GF2Polynomial v = mField.getFieldPolynomial();
			GF2Polynomial h;
			while (true)
			{
				while (!u.testBit(0))
				{ // x|u (x divides u)
					u.shiftRightThis(); // u = u / x
					if (!b.testBit(0))
					{
						b.shiftRightThis();
					}
					else
					{
						b.addToThis(mField.getFieldPolynomial());
						b.shiftRightThis();
					}
				}
				if (u.isOne())
				{
					return new GF2nPolynomialElement((GF2nPolynomialField)mField, b);
				}
				u.reduceN();
				v.reduceN();
				if (u.getLength() < v.getLength())
				{
					h = u;
					u = v;
					v = h;
					h = b;
					b = c;
					c = h;
				}
				u.addToThis(v);
				b.addToThis(c);
			}
		}

		/// <summary>
		/// This method is used internally to map the square()-calls within
		/// GF2nPolynomialElement to one of the possible squaring methods.
		/// </summary>
		/// <returns> <tt>this<sup>2</sup></tt> (newly created) </returns>
		/// <seealso cref= GF2nPolynomialElement#squarePreCalc </seealso>
		public override GF2nElement square()
		{
			return squarePreCalc();
		}

		/// <summary>
		/// This method is used internally to map the square()-calls within
		/// GF2nPolynomialElement to one of the possible squaring methods.
		/// </summary>
		public override void squareThis()
		{
			squareThisPreCalc();
		}

		/// <summary>
		/// Squares this GF2nPolynomialElement using GF2nField's squaring matrix.
		/// This is supposed to be fast when using a polynomial (no tri- or
		/// pentanomial) as fieldpolynomial. Use squarePreCalc when using a tri- or
		/// pentanomial as fieldpolynomial instead.
		/// </summary>
		/// <returns> <tt>this<sup>2</sup></tt> (newly created) </returns>
		/// <seealso cref= GF2Polynomial#vectorMult </seealso>
		/// <seealso cref= GF2nPolynomialElement#squarePreCalc </seealso>
		/// <seealso cref= GF2nPolynomialElement#squareBitwise </seealso>
		public virtual GF2nPolynomialElement squareMatrix()
		{
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.squareThisMatrix();
			result.reduceThis();
			return result;
		}

		/// <summary>
		/// Squares this GF2nPolynomialElement using GF2nFields squaring matrix. This
		/// is supposed to be fast when using a polynomial (no tri- or pentanomial)
		/// as fieldpolynomial. Use squarePreCalc when using a tri- or pentanomial as
		/// fieldpolynomial instead.
		/// </summary>
		/// <seealso cref= GF2Polynomial#vectorMult </seealso>
		/// <seealso cref= GF2nPolynomialElement#squarePreCalc </seealso>
		/// <seealso cref= GF2nPolynomialElement#squareBitwise </seealso>
		public virtual void squareThisMatrix()
		{
			GF2Polynomial result = new GF2Polynomial(mDegree);
			for (int i = 0; i < mDegree; i++)
			{
				if (polynomial.vectorMult(((GF2nPolynomialField)mField).squaringMatrix[mDegree - i - 1]))
				{
					result.setBit(i);

				}
			}
			polynomial = result;
		}

		/// <summary>
		/// Squares this GF2nPolynomialElement by shifting left its Bitstring and
		/// reducing. This is supposed to be the slowest method. Use squarePreCalc or
		/// squareMatrix instead.
		/// </summary>
		/// <returns> <tt>this<sup>2</sup></tt> (newly created) </returns>
		/// <seealso cref= GF2nPolynomialElement#squareMatrix </seealso>
		/// <seealso cref= GF2nPolynomialElement#squarePreCalc </seealso>
		/// <seealso cref= GF2Polynomial#squareThisBitwise </seealso>
		public virtual GF2nPolynomialElement squareBitwise()
		{
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.squareThisBitwise();
			result.reduceThis();
			return result;
		}

		/// <summary>
		/// Squares this GF2nPolynomialElement by shifting left its Bitstring and
		/// reducing. This is supposed to be the slowest method. Use squarePreCalc or
		/// squareMatrix instead.
		/// </summary>
		/// <seealso cref= GF2nPolynomialElement#squareMatrix </seealso>
		/// <seealso cref= GF2nPolynomialElement#squarePreCalc </seealso>
		/// <seealso cref= GF2Polynomial#squareThisBitwise </seealso>
		public virtual void squareThisBitwise()
		{
			polynomial.squareThisBitwise();
			reduceThis();
		}

		/// <summary>
		/// Squares this GF2nPolynomialElement by using precalculated values and
		/// reducing. This is supposed to de fastest when using a trinomial or
		/// pentanomial as field polynomial. Use squareMatrix when using a ordinary
		/// polynomial as field polynomial.
		/// </summary>
		/// <returns> <tt>this<sup>2</sup></tt> (newly created) </returns>
		/// <seealso cref= GF2nPolynomialElement#squareMatrix </seealso>
		/// <seealso cref= GF2Polynomial#squareThisPreCalc </seealso>
		public virtual GF2nPolynomialElement squarePreCalc()
		{
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.squareThisPreCalc();
			result.reduceThis();
			return result;
		}

		/// <summary>
		/// Squares this GF2nPolynomialElement by using precalculated values and
		/// reducing. This is supposed to de fastest when using a tri- or pentanomial
		/// as fieldpolynomial. Use squareMatrix when using a ordinary polynomial as
		/// fieldpolynomial.
		/// </summary>
		/// <seealso cref= GF2nPolynomialElement#squareMatrix </seealso>
		/// <seealso cref= GF2Polynomial#squareThisPreCalc </seealso>
		public virtual void squareThisPreCalc()
		{
			polynomial.squareThisPreCalc();
			reduceThis();
		}

		/// <summary>
		/// Calculates <i>this</i> to the power of <i>k</i> and returns the result
		/// in a new GF2nPolynomialElement.
		/// </summary>
		/// <param name="k"> the power </param>
		/// <returns> <i>this</i>^<i>k</i> in a new GF2nPolynomialElement </returns>
		public virtual GF2nPolynomialElement power(int k)
		{
			if (k == 1)
			{
				return new GF2nPolynomialElement(this);
			}

			GF2nPolynomialElement result = GF2nPolynomialElement.ONE((GF2nPolynomialField)mField);
			if (k == 0)
			{
				return result;
			}

			GF2nPolynomialElement x = new GF2nPolynomialElement(this);
			x.polynomial.expandN((x.mDegree << 1) + 32); // increase performance
			x.polynomial.reduceN();

			for (int i = 0; i < mDegree; i++)
			{
				if ((k & (1 << i)) != 0)
				{
					result.multiplyThisBy(x);
				}
				x.square();
			}

			return result;
		}

		/// <summary>
		/// Compute the square root of this element and return the result in a new
		/// <seealso cref="GF2nPolynomialElement"/>.
		/// </summary>
		/// <returns> <tt>this<sup>1/2</sup></tt> (newly created) </returns>
		public override GF2nElement squareRoot()
		{
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.squareRootThis();
			return result;
		}

		/// <summary>
		/// Compute the square root of this element.
		/// </summary>
		public override void squareRootThis()
		{
			// increase performance
			polynomial.expandN((mDegree << 1) + 32);
			polynomial.reduceN();
			for (int i = 0; i < mField.getDegree() - 1; i++)
			{
				squareThis();
			}
		}

		/// <summary>
		/// Solves the quadratic equation <tt>z<sup>2</sup> + z = this</tt> if
		/// such a solution exists. This method returns one of the two possible
		/// solutions. The other solution is <tt>z + 1</tt>. Use z.increase() to
		/// compute this solution.
		/// </summary>
		/// <returns> a GF2nPolynomialElement representing one z satisfying the
		///         equation <tt>z<sup>2</sup> + z = this</tt> </returns>
		/// <seealso cref= "IEEE 1363, Annex A.4.7" </seealso>
		public override GF2nElement solveQuadraticEquation()
		{
			if (isZero())
			{
				return ZERO((GF2nPolynomialField)mField);
			}

			if ((mDegree & 1) == 1)
			{
				return halfTrace();
			}

			// TODO this can be sped-up by precomputation of p and w's
			GF2nPolynomialElement z, w;
			do
			{
				// step 1.
				GF2nPolynomialElement p = new GF2nPolynomialElement((GF2nPolynomialField)mField, new Random());
				// step 2.
				z = ZERO((GF2nPolynomialField)mField);
				w = (GF2nPolynomialElement)p.clone();
				// step 3.
				for (int i = 1; i < mDegree; i++)
				{
					// compute z = z^2 + w^2 * this
					// and w = w^2 + p
					z.squareThis();
					w.squareThis();
					z.addToThis(w.multiply(this));
					w.addToThis(p);
				}
			} while (w.isZero()); // step 4.

			if (!Equals(z.square().add(z)))
			{
				throw new RuntimeException();
			}

			// step 5.
			return z;
		}

		/// <summary>
		/// Returns the trace of this GF2nPolynomialElement.
		/// </summary>
		/// <returns> the trace of this GF2nPolynomialElement </returns>
		public override int trace()
		{
			GF2nPolynomialElement t = new GF2nPolynomialElement(this);
			int i;

			for (i = 1; i < mDegree; i++)
			{
				t.squareThis();
				t.addToThis(this);
			}

			if (t.isOne())
			{
				return 1;
			}
			return 0;
		}

		/// <summary>
		/// Returns the half-trace of this GF2nPolynomialElement.
		/// </summary>
		/// <returns> a GF2nPolynomialElement representing the half-trace of this
		///         GF2nPolynomialElement. </returns>
		private GF2nPolynomialElement halfTrace()
		{
			if ((mDegree & 0x01) == 0)
			{
				throw new RuntimeException();
			}
			int i;
			GF2nPolynomialElement h = new GF2nPolynomialElement(this);

			for (i = 1; i <= ((mDegree - 1) >> 1); i++)
			{
				h.squareThis();
				h.squareThis();
				h.addToThis(this);
			}

			return h;
		}

		/// <summary>
		/// Reduces this GF2nPolynomialElement modulo the field-polynomial.
		/// </summary>
		/// <seealso cref= GF2Polynomial#reduceTrinomial </seealso>
		/// <seealso cref= GF2Polynomial#reducePentanomial </seealso>
		private void reduceThis()
		{
			if (polynomial.getLength() > mDegree)
			{ // really reduce ?
				if (((GF2nPolynomialField)mField).isTrinomial())
				{ // fieldpolonomial
					// is trinomial
					int tc;
					try
					{
						tc = ((GF2nPolynomialField)mField).getTc();
					}
					catch (RuntimeException)
					{
						throw new RuntimeException("GF2nPolynomialElement.reduce: the field" + " polynomial is not a trinomial");
					}
					if (((mDegree - tc) <= 32) || (polynomial.getLength() > (mDegree << 1)))
					{
						reduceTrinomialBitwise(tc);
						return;
					}
					polynomial.reduceTrinomial(mDegree, tc);
					return;
				}
				else if (((GF2nPolynomialField)mField).isPentanomial())
				{ // fieldpolynomial
					// is
					// pentanomial
					int[] pc;
					try
					{
						pc = ((GF2nPolynomialField)mField).getPc();
					}
					catch (RuntimeException)
					{
						throw new RuntimeException("GF2nPolynomialElement.reduce: the field" + " polynomial is not a pentanomial");
					}
					if (((mDegree - pc[2]) <= 32) || (polynomial.getLength() > (mDegree << 1)))
					{
						reducePentanomialBitwise(pc);
						return;
					}
					polynomial.reducePentanomial(mDegree, pc);
					return;
				}
				else
				{ // fieldpolynomial is something else
					polynomial = polynomial.remainder(mField.getFieldPolynomial());
					polynomial.expandN(mDegree);
					return;
				}
			}
			if (polynomial.getLength() < mDegree)
			{
				polynomial.expandN(mDegree);
			}
		}

		/// <summary>
		/// Reduce this GF2nPolynomialElement using the trinomial x^n + x^tc + 1 as
		/// fieldpolynomial. The coefficients are reduced bit by bit.
		/// </summary>
		private void reduceTrinomialBitwise(int tc)
		{
			int i;
			int k = mDegree - tc;
			for (i = polynomial.getLength() - 1; i >= mDegree; i--)
			{
				if (polynomial.testBit(i))
				{

					polynomial.xorBit(i);
					polynomial.xorBit(i - k);
					polynomial.xorBit(i - mDegree);

				}
			}
			polynomial.reduceN();
			polynomial.expandN(mDegree);
		}

		/// <summary>
		/// Reduce this GF2nPolynomialElement using the pentanomial x^n + x^pc[2] +
		/// x^pc[1] + x^pc[0] + 1 as fieldpolynomial. The coefficients are reduced
		/// bit by bit.
		/// </summary>
		private void reducePentanomialBitwise(int[] pc)
		{
			int i;
			int k = mDegree - pc[2];
			int l = mDegree - pc[1];
			int m = mDegree - pc[0];
			for (i = polynomial.getLength() - 1; i >= mDegree; i--)
			{
				if (polynomial.testBit(i))
				{
					polynomial.xorBit(i);
					polynomial.xorBit(i - k);
					polynomial.xorBit(i - l);
					polynomial.xorBit(i - m);
					polynomial.xorBit(i - mDegree);

				}
			}
			polynomial.reduceN();
			polynomial.expandN(mDegree);
		}

		// /////////////////////////////////////////////////////////////////////
		// conversion
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		/// Returns a string representing this Bitstrings value using hexadecimal
		/// radix in MSB-first order.
		/// </summary>
		/// <returns> a String representing this Bitstrings value. </returns>
		public override string ToString()
		{
			return polynomial.ToString(16);
		}

		/// <summary>
		/// Returns a string representing this Bitstrings value using hexadecimal or
		/// binary radix in MSB-first order.
		/// </summary>
		/// <param name="radix"> the radix to use (2 or 16, otherwise 2 is used) </param>
		/// <returns> a String representing this Bitstrings value. </returns>
		public override string ToString(int radix)
		{
			return polynomial.ToString(radix);
		}

		/// <summary>
		/// Converts this GF2nPolynomialElement to a byte[] according to 1363.
		/// </summary>
		/// <returns> a byte[] representing the value of this GF2nPolynomialElement </returns>
		/// <seealso cref= "P1363 5.5.2 p22f BS2OSP, FE2OSP" </seealso>
		public override byte[] toByteArray()
		{
			return polynomial.toByteArray();
		}

		/// <summary>
		/// Converts this GF2nPolynomialElement to an integer according to 1363.
		/// </summary>
		/// <returns> a BigInteger representing the value of this
		///         GF2nPolynomialElement </returns>
		/// <seealso cref= "P1363 5.5.1 p22 BS2IP" </seealso>
		public override BigInteger toFlexiBigInt()
		{
			return polynomial.toFlexiBigInt();
		}

	}

}