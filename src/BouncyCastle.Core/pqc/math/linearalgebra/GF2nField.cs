using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.math.linearalgebra
{



	/// <summary>
	/// This abstract class defines the finite field <i>GF(2<sup>n</sup>)</i>. It
	/// holds the extension degree <i>n</i>, the characteristic, the irreducible
	/// fieldpolynomial and conversion matrices. GF2nField is implemented by the
	/// classes GF2nPolynomialField and GF2nONBField.
	/// </summary>
	/// <seealso cref= GF2nONBField </seealso>
	/// <seealso cref= GF2nPolynomialField </seealso>
	public abstract class GF2nField
	{

		protected internal readonly SecureRandom random;

		/// <summary>
		/// the degree of this field
		/// </summary>
		protected internal int mDegree;

		/// <summary>
		/// the irreducible fieldPolynomial stored in normal order (also for ONB)
		/// </summary>
		protected internal GF2Polynomial fieldPolynomial;

		/// <summary>
		/// holds a list of GF2nFields to which elements have been converted and thus
		/// a COB-Matrix exists
		/// </summary>
		protected internal Vector fields;

		/// <summary>
		/// the COB matrices
		/// </summary>
		protected internal Vector matrices;

		public GF2nField(SecureRandom random)
		{
			this.random = random;
		}

		/// <summary>
		/// Returns the degree <i>n</i> of this field.
		/// </summary>
		/// <returns> the degree <i>n</i> of this field </returns>
		public int getDegree()
		{
			return mDegree;
		}

		/// <summary>
		/// Returns the fieldpolynomial as a new Bitstring.
		/// </summary>
		/// <returns> a copy of the fieldpolynomial as a new Bitstring </returns>
		public GF2Polynomial getFieldPolynomial()
		{
			if (fieldPolynomial == null)
			{
				computeFieldPolynomial();
			}
			return new GF2Polynomial(fieldPolynomial);
		}

		/// <summary>
		/// Decides whether the given object <tt>other</tt> is the same as this
		/// field.
		/// </summary>
		/// <param name="other"> another object </param>
		/// <returns> (this == other) </returns>
		public sealed override bool Equals(object other)
		{
			if (other == null || !(other is GF2nField))
			{
				return false;
			}

			GF2nField otherField = (GF2nField)other;

			if (otherField.mDegree != mDegree)
			{
				return false;
			}
			if (!fieldPolynomial.Equals(otherField.fieldPolynomial))
			{
				return false;
			}
			if ((this is GF2nPolynomialField) && !(otherField is GF2nPolynomialField))
			{
				return false;
			}
			if ((this is GF2nONBField) && !(otherField is GF2nONBField))
			{
				return false;
			}
			return true;
		}

		/// <returns> the hash code of this field </returns>
		public override int GetHashCode()
		{
			return mDegree + fieldPolynomial.GetHashCode();
		}

		/// <summary>
		/// Computes a random root from the given irreducible fieldpolynomial
		/// according to IEEE 1363 algorithm A.5.6. This cal take very long for big
		/// degrees.
		/// </summary>
		/// <param name="B0FieldPolynomial"> the fieldpolynomial if the other basis as a Bitstring </param>
		/// <returns> a random root of BOFieldPolynomial in representation according to
		///         this field </returns>
		/// <seealso cref= "P1363 A.5.6, p103f" </seealso>
		public abstract GF2nElement getRandomRoot(GF2Polynomial B0FieldPolynomial);

		/// <summary>
		/// Computes the change-of-basis matrix for basis conversion according to
		/// 1363. The result is stored in the lists fields and matrices.
		/// </summary>
		/// <param name="B1"> the GF2nField to convert to </param>
		/// <seealso cref= "P1363 A.7.3, p111ff" </seealso>
		public abstract void computeCOBMatrix(GF2nField B1);

		/// <summary>
		/// Computes the fieldpolynomial. This can take a long time for big degrees.
		/// </summary>
		public abstract void computeFieldPolynomial();

		/// <summary>
		/// Inverts the given matrix represented as bitstrings.
		/// </summary>
		/// <param name="matrix"> the matrix to invert as a Bitstring[] </param>
		/// <returns> matrix^(-1) </returns>
		public GF2Polynomial[] invertMatrix(GF2Polynomial[] matrix)
		{
			GF2Polynomial[] a = new GF2Polynomial[matrix.Length];
			GF2Polynomial[] inv = new GF2Polynomial[matrix.Length];
			GF2Polynomial dummy;
			int i, j;
			// initialize a as a copy of matrix and inv as E(inheitsmatrix)
			for (i = 0; i < mDegree; i++)
			{
				a[i] = new GF2Polynomial(matrix[i]);
				inv[i] = new GF2Polynomial(mDegree);
				inv[i].setBit(mDegree - 1 - i);
			}
			// construct triangle matrix so that for each a[i] the first i bits are
			// zero
			for (i = 0; i < mDegree - 1; i++)
			{
				// find column where bit i is set
				j = i;
				while ((j < mDegree) && !a[j].testBit(mDegree - 1 - i))
				{
					j++;
				}
				if (j >= mDegree)
				{
					throw new RuntimeException("GF2nField.invertMatrix: Matrix cannot be inverted!");
				}
				if (i != j)
				{ // swap a[i]/a[j] and inv[i]/inv[j]
					dummy = a[i];
					a[i] = a[j];
					a[j] = dummy;
					dummy = inv[i];
					inv[i] = inv[j];
					inv[j] = dummy;
				}
				for (j = i + 1; j < mDegree; j++)
				{ // add column i to all columns>i
					// having their i-th bit set
					if (a[j].testBit(mDegree - 1 - i))
					{
						a[j].addToThis(a[i]);
						inv[j].addToThis(inv[i]);
					}
				}
			}
			// construct Einheitsmatrix from a
			for (i = mDegree - 1; i > 0; i--)
			{
				for (j = i - 1; j >= 0; j--)
				{ // eliminate the i-th bit in all
					// columns < i
					if (a[j].testBit(mDegree - 1 - i))
					{
						a[j].addToThis(a[i]);
						inv[j].addToThis(inv[i]);
					}
				}
			}
			return inv;
		}

		/// <summary>
		/// Converts the given element in representation according to this field to a
		/// new element in representation according to B1 using the change-of-basis
		/// matrix calculated by computeCOBMatrix.
		/// </summary>
		/// <param name="elem">  the GF2nElement to convert </param>
		/// <param name="basis"> the basis to convert <tt>elem</tt> to </param>
		/// <returns> <tt>elem</tt> converted to a new element representation
		///         according to <tt>basis</tt> </returns>
		/// <seealso cref= GF2nField#computeCOBMatrix </seealso>
		/// <seealso cref= GF2nField#getRandomRoot </seealso>
		/// <seealso cref= GF2nPolynomial </seealso>
		/// <seealso cref= "P1363 A.7 p109ff" </seealso>
		public GF2nElement convert(GF2nElement elem, GF2nField basis)
		{
			if (basis == this)
			{
				return (GF2nElement)elem.clone();
			}
			if (fieldPolynomial.Equals(basis.fieldPolynomial))
			{
				return (GF2nElement)elem.clone();
			}
			if (mDegree != basis.mDegree)
			{
				throw new RuntimeException("GF2nField.convert: B1 has a" + " different degree and thus cannot be coverted to!");
			}

			int i;
			GF2Polynomial[] COBMatrix;
			i = fields.indexOf(basis);
			if (i == -1)
			{
				computeCOBMatrix(basis);
				i = fields.indexOf(basis);
			}
			COBMatrix = (GF2Polynomial[])matrices.elementAt(i);

			GF2nElement elemCopy = (GF2nElement)elem.clone();
			if (elemCopy is GF2nONBElement)
			{
				// remember: ONB treats its bits in reverse order
				((GF2nONBElement)elemCopy).reverseOrder();
			}
			GF2Polynomial bs = new GF2Polynomial(mDegree, elemCopy.toFlexiBigInt());
			bs.expandN(mDegree);
			GF2Polynomial result = new GF2Polynomial(mDegree);
			for (i = 0; i < mDegree; i++)
			{
				if (bs.vectorMult(COBMatrix[i]))
				{
					result.setBit(mDegree - 1 - i);
				}
			}
			if (basis is GF2nPolynomialField)
			{
				return new GF2nPolynomialElement((GF2nPolynomialField)basis, result);
			}
			else if (basis is GF2nONBField)
			{
				GF2nONBElement res = new GF2nONBElement((GF2nONBField)basis, result.toFlexiBigInt());
				// TODO Remember: ONB treats its Bits in reverse order !!!
				res.reverseOrder();
				return res;
			}
			else
			{
				throw new RuntimeException("GF2nField.convert: B1 must be an instance of " + "GF2nPolynomialField or GF2nONBField!");
			}

		}

	}

}