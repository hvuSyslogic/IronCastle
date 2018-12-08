using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec
{

	/// <summary>
	/// Class representing a simple version of a big decimal. A
	/// <code>SimpleBigDecimal</code> is basically a
	/// <seealso cref="BigInteger"/> with a few digits on the right of
	/// the decimal point. The number of (binary) digits on the right of the decimal
	/// point is called the <code>scale</code> of the <code>SimpleBigDecimal</code>.
	/// Unlike in <seealso cref="java.math.BigDecimal BigDecimal"/>, the scale is not adjusted
	/// automatically, but must be set manually. All <code>SimpleBigDecimal</code>s
	/// taking part in the same arithmetic operation must have equal scale. The
	/// result of a multiplication of two <code>SimpleBigDecimal</code>s returns a
	/// <code>SimpleBigDecimal</code> with double scale.
	/// </summary>
	public class SimpleBigDecimal
	{
		//extends Number   // not in J2ME - add compatibility class?
		private const long serialVersionUID = 1L;

		private readonly BigInteger bigInt;
		private readonly int scale;

		/// <summary>
		/// Returns a <code>SimpleBigDecimal</code> representing the same numerical
		/// value as <code>value</code>. </summary>
		/// <param name="value"> The value of the <code>SimpleBigDecimal</code> to be
		/// created. </param>
		/// <param name="scale"> The scale of the <code>SimpleBigDecimal</code> to be
		/// created. </param>
		/// <returns> The such created <code>SimpleBigDecimal</code>. </returns>
		public static SimpleBigDecimal getInstance(BigInteger value, int scale)
		{
			return new SimpleBigDecimal(value.shiftLeft(scale), scale);
		}

		/// <summary>
		/// Constructor for <code>SimpleBigDecimal</code>. The value of the
		/// constructed <code>SimpleBigDecimal</code> equals <code>bigInt / 
		/// 2<sup>scale</sup></code>. </summary>
		/// <param name="bigInt"> The <code>bigInt</code> value parameter. </param>
		/// <param name="scale"> The scale of the constructed <code>SimpleBigDecimal</code>. </param>
		public SimpleBigDecimal(BigInteger bigInt, int scale)
		{
			if (scale < 0)
			{
				throw new IllegalArgumentException("scale may not be negative");
			}

			this.bigInt = bigInt;
			this.scale = scale;
		}

		private void checkScale(SimpleBigDecimal b)
		{
			if (scale != b.scale)
			{
				throw new IllegalArgumentException("Only SimpleBigDecimal of " + "same scale allowed in arithmetic operations");
			}
		}

		public virtual SimpleBigDecimal adjustScale(int newScale)
		{
			if (newScale < 0)
			{
				throw new IllegalArgumentException("scale may not be negative");
			}

			if (newScale == scale)
			{
				return this;
			}

			return new SimpleBigDecimal(bigInt.shiftLeft(newScale - scale), newScale);
		}

		public virtual SimpleBigDecimal add(SimpleBigDecimal b)
		{
			checkScale(b);
			return new SimpleBigDecimal(bigInt.add(b.bigInt), scale);
		}

		public virtual SimpleBigDecimal add(BigInteger b)
		{
			return new SimpleBigDecimal(bigInt.add(b.shiftLeft(scale)), scale);
		}

		public virtual SimpleBigDecimal negate()
		{
			return new SimpleBigDecimal(bigInt.negate(), scale);
		}

		public virtual SimpleBigDecimal subtract(SimpleBigDecimal b)
		{
			return add(b.negate());
		}

		public virtual SimpleBigDecimal subtract(BigInteger b)
		{
			return new SimpleBigDecimal(bigInt.subtract(b.shiftLeft(scale)), scale);
		}

		public virtual SimpleBigDecimal multiply(SimpleBigDecimal b)
		{
			checkScale(b);
			return new SimpleBigDecimal(bigInt.multiply(b.bigInt), scale + scale);
		}

		public virtual SimpleBigDecimal multiply(BigInteger b)
		{
			return new SimpleBigDecimal(bigInt.multiply(b), scale);
		}

		public virtual SimpleBigDecimal divide(SimpleBigDecimal b)
		{
			checkScale(b);
			BigInteger dividend = bigInt.shiftLeft(scale);
			return new SimpleBigDecimal(dividend.divide(b.bigInt), scale);
		}

		public virtual SimpleBigDecimal divide(BigInteger b)
		{
			return new SimpleBigDecimal(bigInt.divide(b), scale);
		}

		public virtual SimpleBigDecimal shiftLeft(int n)
		{
			return new SimpleBigDecimal(bigInt.shiftLeft(n), scale);
		}

		public virtual int compareTo(SimpleBigDecimal val)
		{
			checkScale(val);
			return bigInt.compareTo(val.bigInt);
		}

		public virtual int compareTo(BigInteger val)
		{
			return bigInt.compareTo(val.shiftLeft(scale));
		}

		public virtual BigInteger floor()
		{
			return bigInt.shiftRight(scale);
		}

		public virtual BigInteger round()
		{
			SimpleBigDecimal oneHalf = new SimpleBigDecimal(ECConstants_Fields.ONE, 1);
			return add(oneHalf.adjustScale(scale)).floor();
		}

		public virtual int intValue()
		{
			return floor().intValue();
		}

		public virtual long longValue()
		{
			return floor().longValue();
		}
			  /* NON-J2ME compliant.
		public double doubleValue()
		{
			return Double.valueOf(toString()).doubleValue();
		}
	
		public float floatValue()
		{
			return Float.valueOf(toString()).floatValue();
		}
		   */
		public virtual int getScale()
		{
			return scale;
		}

		public override string ToString()
		{
			if (scale == 0)
			{
				return bigInt.ToString();
			}

			BigInteger floorBigInt = floor();

			BigInteger fract = bigInt.subtract(floorBigInt.shiftLeft(scale));
			if (bigInt.signum() == -1)
			{
				fract = ECConstants_Fields.ONE.shiftLeft(scale).subtract(fract);
			}

			if ((floorBigInt.signum() == -1) && (!(fract.Equals(ECConstants_Fields.ZERO))))
			{
				floorBigInt = floorBigInt.add(ECConstants_Fields.ONE);
			}
			string leftOfPoint = floorBigInt.ToString();

			char[] fractCharArr = new char[scale];
			string fractStr = fract.ToString(2);
			int fractLen = fractStr.Length;
			int zeroes = scale - fractLen;
			for (int i = 0; i < zeroes; i++)
			{
				fractCharArr[i] = '0';
			}
			for (int j = 0; j < fractLen; j++)
			{
				fractCharArr[zeroes + j] = fractStr[j];
			}
			string rightOfPoint = new string(fractCharArr);

			StringBuffer sb = new StringBuffer(leftOfPoint);
			sb.append(".");
			sb.append(rightOfPoint);

			return sb.ToString();
		}

		public override bool Equals(object o)
		{
			if (this == o)
			{
				return true;
			}

			if (!(o is SimpleBigDecimal))
			{
				return false;
			}

			SimpleBigDecimal other = (SimpleBigDecimal)o;
			return ((bigInt.Equals(other.bigInt)) && (scale == other.scale));
		}

		public override int GetHashCode()
		{
			return bigInt.GetHashCode() ^ scale;
		}

	}

}