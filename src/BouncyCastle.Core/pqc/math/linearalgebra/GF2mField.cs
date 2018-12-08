using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.math.linearalgebra
{

	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;

	/// <summary>
	/// This class describes operations with elements from the finite field F =
	/// GF(2^m). ( GF(2^m)= GF(2)[A] where A is a root of irreducible polynomial with
	/// degree m, each field element B has a polynomial basis representation, i.e. it
	/// is represented by a different binary polynomial of degree less than m, B =
	/// poly(A) ) All operations are defined only for field with 1&lt; m &lt;32. For the
	/// representation of field elements the map f: F-&gt;Z, poly(A)-&gt;poly(2) is used,
	/// where integers have the binary representation. For example: A^7+A^3+A+1 -&gt;
	/// (00...0010001011)=139 Also for elements type Integer is used.
	/// </summary>
	/// <seealso cref= PolynomialRingGF2 </seealso>
	public class GF2mField
	{

		/*
		  * degree - degree of the field polynomial - the field polynomial ring -
		  * polynomial ring over the finite field GF(2)
		  */

		private int degree = 0;

		private int polynomial;

		/// <summary>
		/// create a finite field GF(2^m)
		/// </summary>
		/// <param name="degree"> the degree of the field </param>
		public GF2mField(int degree)
		{
			if (degree >= 32)
			{
				throw new IllegalArgumentException(" Error: the degree of field is too large ");
			}
			if (degree < 1)
			{
				throw new IllegalArgumentException(" Error: the degree of field is non-positive ");
			}
			this.degree = degree;
			polynomial = PolynomialRingGF2.getIrreduciblePolynomial(degree);
		}

		/// <summary>
		/// create a finite field GF(2^m) with the fixed field polynomial
		/// </summary>
		/// <param name="degree"> the degree of the field </param>
		/// <param name="poly">   the field polynomial </param>
		public GF2mField(int degree, int poly)
		{
			if (degree != PolynomialRingGF2.degree(poly))
			{
				throw new IllegalArgumentException(" Error: the degree is not correct");
			}
			if (!PolynomialRingGF2.isIrreducible(poly))
			{
				throw new IllegalArgumentException(" Error: given polynomial is reducible");
			}
			this.degree = degree;
			polynomial = poly;

		}

		public GF2mField(byte[] enc)
		{
			if (enc.Length != 4)
			{
				throw new IllegalArgumentException("byte array is not an encoded finite field");
			}
			polynomial = LittleEndianConversions.OS2IP(enc);
			if (!PolynomialRingGF2.isIrreducible(polynomial))
			{
				throw new IllegalArgumentException("byte array is not an encoded finite field");
			}

			degree = PolynomialRingGF2.degree(polynomial);
		}

		public GF2mField(GF2mField field)
		{
			degree = field.degree;
			polynomial = field.polynomial;
		}

		/// <summary>
		/// return degree of the field
		/// </summary>
		/// <returns> degree of the field </returns>
		public virtual int getDegree()
		{
			return degree;
		}

		/// <summary>
		/// return the field polynomial
		/// </summary>
		/// <returns> the field polynomial </returns>
		public virtual int getPolynomial()
		{
			return polynomial;
		}

		/// <summary>
		/// return the encoded form of this field
		/// </summary>
		/// <returns> the field in byte array form </returns>
		public virtual byte[] getEncoded()
		{
			return LittleEndianConversions.I2OSP(polynomial);
		}

		/// <summary>
		/// Return sum of two elements
		/// </summary>
		/// <param name="a"> </param>
		/// <param name="b"> </param>
		/// <returns> a+b </returns>
		public virtual int add(int a, int b)
		{
			return a ^ b;
		}

		/// <summary>
		/// Return product of two elements
		/// </summary>
		/// <param name="a"> </param>
		/// <param name="b"> </param>
		/// <returns> a*b </returns>
		public virtual int mult(int a, int b)
		{
			return PolynomialRingGF2.modMultiply(a, b, polynomial);
		}

		/// <summary>
		/// compute exponentiation a^k
		/// </summary>
		/// <param name="a"> a field element a </param>
		/// <param name="k"> k degree </param>
		/// <returns> a^k </returns>
		public virtual int exp(int a, int k)
		{
			if (k == 0)
			{
				return 1;
			}
			if (a == 0)
			{
				return 0;
			}
			if (a == 1)
			{
				return 1;
			}
			int result = 1;
			if (k < 0)
			{
				a = inverse(a);
				k = -k;
			}
			while (k != 0)
			{
				if ((k & 1) == 1)
				{
					result = mult(result, a);
				}
				a = mult(a, a);
				k = (int)((uint)k >> 1);
			}
			return result;
		}

		/// <summary>
		/// compute the multiplicative inverse of a
		/// </summary>
		/// <param name="a"> a field element a </param>
		/// <returns> a<sup>-1</sup> </returns>
		public virtual int inverse(int a)
		{
			int d = (1 << degree) - 2;

			return exp(a, d);
		}

		/// <summary>
		/// compute the square root of an integer
		/// </summary>
		/// <param name="a"> a field element a </param>
		/// <returns> a<sup>1/2</sup> </returns>
		public virtual int sqRoot(int a)
		{
			for (int i = 1; i < degree; i++)
			{
				a = mult(a, a);
			}
			return a;
		}

		/// <summary>
		/// create a random field element using PRNG sr
		/// </summary>
		/// <param name="sr"> SecureRandom </param>
		/// <returns> a random element </returns>
		public virtual int getRandomElement(SecureRandom sr)
		{
			int result = RandUtils.nextInt(sr, 1 << degree);
			return result;
		}

		/// <summary>
		/// create a random non-zero field element
		/// </summary>
		/// <returns> a random element </returns>
		public virtual int getRandomNonZeroElement()
		{
			return getRandomNonZeroElement(CryptoServicesRegistrar.getSecureRandom());
		}

		/// <summary>
		/// create a random non-zero field element using PRNG sr
		/// </summary>
		/// <param name="sr"> SecureRandom </param>
		/// <returns> a random non-zero element </returns>
		public virtual int getRandomNonZeroElement(SecureRandom sr)
		{
			int controltime = 1 << 20;
			int count = 0;
			int result = RandUtils.nextInt(sr, 1 << degree);
			while ((result == 0) && (count < controltime))
			{
				result = RandUtils.nextInt(sr, 1 << degree);
				count++;
			}
			if (count == controltime)
			{
				result = 1;
			}
			return result;
		}

		/// <returns> true if e is encoded element of this field and false otherwise </returns>
		public virtual bool isElementOfThisField(int e)
		{
			// e is encoded element of this field iff 0<= e < |2^m|
			if (degree == 31)
			{
				return e >= 0;
			}
			return e >= 0 && e < (1 << degree);
		}

		/*
		  * help method for visual control
		  */
		public virtual string elementToStr(int a)
		{
			string s = "";
			for (int i = 0; i < degree; i++)
			{
				if (((byte)a & 0x01) == 0)
				{
					s = "0" + s;
				}
				else
				{
					s = "1" + s;
				}
				a = (int)((uint)a >> 1);
			}
			return s;
		}

		/// <summary>
		/// checks if given object is equal to this field.
		/// <para>
		/// The method returns false whenever the given object is not GF2m.
		/// 
		/// </para>
		/// </summary>
		/// <param name="other"> object </param>
		/// <returns> true or false </returns>
		public override bool Equals(object other)
		{
			if ((other == null) || !(other is GF2mField))
			{
				return false;
			}

			GF2mField otherField = (GF2mField)other;

			if ((degree == otherField.degree) && (polynomial == otherField.polynomial))
			{
				return true;
			}

			return false;
		}

		public override int GetHashCode()
		{
			return polynomial;
		}

		/// <summary>
		/// Returns a human readable form of this field.
		/// </summary>
		/// <returns> a human readable form of this field. </returns>
		public override string ToString()
		{
			string str = "Finite Field GF(2^" + degree + ") = " + "GF(2)[X]/<"
				+ polyToString(polynomial) + "> ";
			return str;
		}

		private static string polyToString(int p)
		{
			string str = "";
			if (p == 0)
			{
				str = "0";
			}
			else
			{
				byte b = (byte)(p & 0x01);
				if (b == 1)
				{
					str = "1";
				}
				p = (int)((uint)p >> 1);
				int i = 1;
				while (p != 0)
				{
					b = (byte)(p & 0x01);
					if (b == 1)
					{
						str = str + "+x^" + i;
					}
					p = (int)((uint)p >> 1);
					i++;
				}
			}
			return str;
		}

	}

}