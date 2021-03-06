﻿using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using Random = org.bouncycastle.Port.java.util.Random;

namespace org.bouncycastle.pqc.math.linearalgebra
{


	

	/// <summary>
	/// This class stores very long strings of bits and does some basic arithmetics.
	/// It is used by <tt>GF2nField</tt>, <tt>GF2nPolynomialField</tt> and
	/// <tt>GFnPolynomialElement</tt>.
	/// </summary>
	/// <seealso cref= GF2nPolynomialElement </seealso>
	/// <seealso cref= GF2nField </seealso>
	public class GF2Polynomial
	{

		// number of bits stored in this GF2Polynomial
		private int len;

		// number of int used in value
		private int blocks;

		// storage
		private int[] value;

		// Random source
		private static Random rand = new Random();

		// Lookup-Table for vectorMult: parity[a]= #1(a) mod 2 == 1
		private static readonly bool[] parity = new bool[] {false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false};

		// Lookup-Table for Squaring: squaringTable[a]=a^2
		private static readonly short[] squaringTable = new short[] {0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015, 0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055, 0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115, 0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155, 0x0400, 0x0401, 0x0404, 0x0405, 0x0410, 0x0411, 0x0414, 0x0415, 0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455, 0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515, 0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554, 0x0555, 0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015, 0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055, 0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115, 0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155, 0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415, 0x1440, 0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455, 0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515, 0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555, 0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014, 0x4015, 0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055, 0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115, 0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155, 0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415, 0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455, 0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515, 0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555, 0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015, 0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054, 0x5055, 0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115, 0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155, 0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415, 0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455, 0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515, 0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555};

		// pre-computed Bitmask for fast masking, bitMask[a]=0x1 << a
		private static readonly int[] bitMask = new int[] {0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00002000, 0x00004000, 0x00008000, 0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000, 0x00800000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, unchecked((int)0x80000000), 0x00000000};

		// pre-computed Bitmask for fast masking, rightMask[a]=0xffffffff >>> (32-a)
		private static readonly int[] reverseRightMask = new int[] {0x00000000, 0x00000001, 0x00000003, 0x00000007, 0x0000000f, 0x0000001f, 0x0000003f, 0x0000007f, 0x000000ff, 0x000001ff, 0x000003ff, 0x000007ff, 0x00000fff, 0x00001fff, 0x00003fff, 0x00007fff, 0x0000ffff, 0x0001ffff, 0x0003ffff, 0x0007ffff, 0x000fffff, 0x001fffff, 0x003fffff, 0x007fffff, 0x00ffffff, 0x01ffffff, 0x03ffffff, 0x07ffffff, 0x0fffffff, 0x1fffffff, 0x3fffffff, 0x7fffffff, unchecked((int)0xffffffff)};

		/// <summary>
		/// Creates a new GF2Polynomial of the given <i>length</i> and value zero.
		/// </summary>
		/// <param name="length"> the desired number of bits to store </param>
		public GF2Polynomial(int length)
		{
			int l = length;
			if (l < 1)
			{
				l = 1;
			}
			blocks = ((l - 1) >> 5) + 1;
			value = new int[blocks];
			len = l;
		}

		/// <summary>
		/// Creates a new GF2Polynomial of the given <i>length</i> and random value.
		/// </summary>
		/// <param name="length"> the desired number of bits to store </param>
		/// <param name="rand">   SecureRandom to use for randomization </param>
		public GF2Polynomial(int length, Random rand)
		{
			int l = length;
			if (l < 1)
			{
				l = 1;
			}
			blocks = ((l - 1) >> 5) + 1;
			value = new int[blocks];
			len = l;
			randomize(rand);
		}

		/// <summary>
		/// Creates a new GF2Polynomial of the given <i>length</i> and value
		/// selected by <i>value</i>:
		/// <UL>
		/// <LI>ZERO</LI>
		/// <LI>ONE</LI>
		/// <LI>RANDOM</LI>
		/// <LI>X</LI>
		/// <LI>ALL</LI>
		/// </UL>
		/// </summary>
		/// <param name="length"> the desired number of bits to store </param>
		/// <param name="value">  the value described by a String </param>
		public GF2Polynomial(int length, string value)
		{
			int l = length;
			if (l < 1)
			{
				l = 1;
			}
			blocks = ((l - 1) >> 5) + 1;
			this.value = new int[blocks];
			len = l;
			if (value.Equals("ZERO", StringComparison.OrdinalIgnoreCase))
			{
				assignZero();
			}
			else if (value.Equals("ONE", StringComparison.OrdinalIgnoreCase))
			{
				assignOne();
			}
			else if (value.Equals("RANDOM", StringComparison.OrdinalIgnoreCase))
			{
				randomize();
			}
			else if (value.Equals("X", StringComparison.OrdinalIgnoreCase))
			{
				assignX();
			}
			else if (value.Equals("ALL", StringComparison.OrdinalIgnoreCase))
			{
				assignAll();
			}
			else
			{
				throw new IllegalArgumentException("Error: GF2Polynomial was called using " + value + " as value!");
			}

		}

		/// <summary>
		/// Creates a new GF2Polynomial of the given <i>length</i> using the given
		/// int[]. LSB is contained in bs[0].
		/// </summary>
		/// <param name="length"> the desired number of bits to store </param>
		/// <param name="bs">     contains the desired value, LSB in bs[0] </param>
		public GF2Polynomial(int length, int[] bs)
		{
			int leng = length;
			if (leng < 1)
			{
				leng = 1;
			}
			blocks = ((leng - 1) >> 5) + 1;
			value = new int[blocks];
			len = leng;
			int l = Math.Min(blocks, bs.Length);
			JavaSystem.arraycopy(bs, 0, value, 0, l);
			zeroUnusedBits();
		}

		/// <summary>
		/// Creates a new GF2Polynomial by converting the given byte[] <i>os</i>
		/// according to 1363 and using the given <i>length</i>.
		/// </summary>
		/// <param name="length"> the intended length of this polynomial </param>
		/// <param name="os">     the octet string to assign to this polynomial </param>
		/// <seealso cref= "P1363 5.5.2 p22f, OS2BSP" </seealso>
		public GF2Polynomial(int length, byte[] os)
		{
			int l = length;
			if (l < 1)
			{
				l = 1;
			}
			blocks = ((l - 1) >> 5) + 1;
			value = new int[blocks];
			len = l;
			int i, m;
			int k = Math.Min(((os.Length - 1) >> 2) + 1, blocks);
			for (i = 0; i < k - 1; i++)
			{
				m = os.Length - (i << 2) - 1;
				value[i] = (os[m]) & 0x000000ff;
				value[i] |= (os[m - 1] << 8) & 0x0000ff00;
				value[i] |= (os[m - 2] << 16) & 0x00ff0000;
				value[i] |= unchecked((int)((os[m - 3] << 24) & 0xff000000));
			}
			i = k - 1;
			m = os.Length - (i << 2) - 1;
			value[i] = os[m] & 0x000000ff;
			if (m > 0)
			{
				value[i] |= (os[m - 1] << 8) & 0x0000ff00;
			}
			if (m > 1)
			{
				value[i] |= (os[m - 2] << 16) & 0x00ff0000;
			}
			if (m > 2)
			{
				value[i] |= unchecked((int)((os[m - 3] << 24) & 0xff000000));
			}
			zeroUnusedBits();
			reduceN();
		}

		/// <summary>
		/// Creates a new GF2Polynomial by converting the given FlexiBigInt <i>bi</i>
		/// according to 1363 and using the given <i>length</i>.
		/// </summary>
		/// <param name="length"> the intended length of this polynomial </param>
		/// <param name="bi">     the FlexiBigInt to assign to this polynomial </param>
		/// <seealso cref= "P1363 5.5.1 p22, I2BSP" </seealso>
		public GF2Polynomial(int length, BigInteger bi)
		{
			int l = length;
			if (l < 1)
			{
				l = 1;
			}
			blocks = ((l - 1) >> 5) + 1;
			value = new int[blocks];
			len = l;
			int i;
			byte[] val = bi.toByteArray();
			if (val[0] == 0)
			{
				byte[] dummy = new byte[val.Length - 1];
				JavaSystem.arraycopy(val, 1, dummy, 0, dummy.Length);
				val = dummy;
			}
			int ov = val.Length & 0x03;
			int k = ((val.Length - 1) >> 2) + 1;
			for (i = 0; i < ov; i++)
			{
				value[k - 1] |= (val[i] & 0x000000ff) << ((ov - 1 - i) << 3);
			}
			int m = 0;
			for (i = 0; i <= (val.Length - 4) >> 2; i++)
			{
				m = val.Length - 1 - (i << 2);
				value[i] = (val[m]) & 0x000000ff;
				value[i] |= ((val[m - 1]) << 8) & 0x0000ff00;
				value[i] |= ((val[m - 2]) << 16) & 0x00ff0000;
				value[i] |= unchecked((int)(((val[m - 3]) << 24) & 0xff000000));
			}
			if ((len & 0x1f) != 0)
			{
				value[blocks - 1] &= reverseRightMask[len & 0x1f];
			}
			reduceN();
		}

		/// <summary>
		/// Creates a new GF2Polynomial by cloneing the given GF2Polynomial <i>b</i>.
		/// </summary>
		/// <param name="b"> the GF2Polynomial to clone </param>
		public GF2Polynomial(GF2Polynomial b)
		{
			len = b.len;
			blocks = b.blocks;
			value = IntUtils.clone(b.value);
		}

		/// <returns> a copy of this GF2Polynomial </returns>
		public virtual object clone()
		{
			return new GF2Polynomial(this);
		}

		/// <summary>
		/// Returns the length of this GF2Polynomial. The length can be greater than
		/// the degree. To get the degree call reduceN() before calling getLength().
		/// </summary>
		/// <returns> the length of this GF2Polynomial </returns>
		public virtual int getLength()
		{
			return len;
		}

		/// <summary>
		/// Returns the value of this GF2Polynomial in an int[].
		/// </summary>
		/// <returns> the value of this GF2Polynomial in a new int[], LSB in int[0] </returns>
		public virtual int[] toIntegerArray()
		{
			int[] result;
			result = new int[blocks];
			JavaSystem.arraycopy(value, 0, result, 0, blocks);
			return result;
		}

		/// <summary>
		/// Returns a string representing this GF2Polynomials value using hexadecimal
		/// or binary radix in MSB-first order.
		/// </summary>
		/// <param name="radix"> the radix to use (2 or 16, otherwise 2 is used) </param>
		/// <returns> a String representing this GF2Polynomials value. </returns>
		public virtual string ToString(int radix)
		{

			char[] HEX_CHARS = new char[] {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

			string[] BIN_CHARS = new string[] {"0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"};
			string res;
			int i;
			res = "";
			if (radix == 16)
			{
				for (i = blocks - 1; i >= 0; i--)
				{
					res += HEX_CHARS[((int)((uint)value[i] >> 28)) & 0x0f];
					res += HEX_CHARS[((int)((uint)value[i] >> 24)) & 0x0f];
					res += HEX_CHARS[((int)((uint)value[i] >> 20)) & 0x0f];
					res += HEX_CHARS[((int)((uint)value[i] >> 16)) & 0x0f];
					res += HEX_CHARS[((int)((uint)value[i] >> 12)) & 0x0f];
					res += HEX_CHARS[((int)((uint)value[i] >> 8)) & 0x0f];
					res += HEX_CHARS[((int)((uint)value[i] >> 4)) & 0x0f];
					res += HEX_CHARS[(value[i]) & 0x0f];
					res += " ";
				}
			}
			else
			{
				for (i = blocks - 1; i >= 0; i--)
				{
					res += BIN_CHARS[((int)((uint)value[i] >> 28)) & 0x0f];
					res += BIN_CHARS[((int)((uint)value[i] >> 24)) & 0x0f];
					res += BIN_CHARS[((int)((uint)value[i] >> 20)) & 0x0f];
					res += BIN_CHARS[((int)((uint)value[i] >> 16)) & 0x0f];
					res += BIN_CHARS[((int)((uint)value[i] >> 12)) & 0x0f];
					res += BIN_CHARS[((int)((uint)value[i] >> 8)) & 0x0f];
					res += BIN_CHARS[((int)((uint)value[i] >> 4)) & 0x0f];
					res += BIN_CHARS[(value[i]) & 0x0f];
					res += " ";
				}
			}
			return res;
		}

		/// <summary>
		/// Converts this polynomial to a byte[] (octet string) according to 1363.
		/// </summary>
		/// <returns> a byte[] representing the value of this polynomial </returns>
		/// <seealso cref= "P1363 5.5.2 p22f, BS2OSP" </seealso>
		public virtual byte[] toByteArray()
		{
			int k = ((len - 1) >> 3) + 1;
			int ov = k & 0x03;
			int m;
			byte[] res = new byte[k];
			int i;
			for (i = 0; i < (k >> 2); i++)
			{
				m = k - (i << 2) - 1;
				res[m] = unchecked((byte)((value[i] & 0x000000ff)));
				res[m - 1] = (byte)((int)((uint)(value[i] & 0x0000ff00) >> 8));
				res[m - 2] = (byte)((int)((uint)(value[i] & 0x00ff0000) >> 16));
				res[m - 3] = (byte)((long)((ulong)(value[i] & 0xff000000) >> 24));
			}
			for (i = 0; i < ov; i++)
			{
				m = (ov - i - 1) << 3;
				res[i] = (byte)((int)((uint)(value[blocks - 1] & (0x000000ff << m)) >> m));
			}
			return res;
		}

		/// <summary>
		/// Converts this polynomial to an integer according to 1363.
		/// </summary>
		/// <returns> a FlexiBigInt representing the value of this polynomial </returns>
		/// <seealso cref= "P1363 5.5.1 p22, BS2IP" </seealso>
		public virtual BigInteger toFlexiBigInt()
		{
			if (len == 0 || isZero())
			{
				return new BigInteger(0, new byte[0]);
			}
			return new BigInteger(1, toByteArray());
		}

		/// <summary>
		/// Sets the LSB to 1 and all other to 0, assigning 'one' to this
		/// GF2Polynomial.
		/// </summary>
		public virtual void assignOne()
		{
			int i;
			for (i = 1; i < blocks; i++)
			{
				value[i] = 0x00;
			}
			value[0] = 0x01;
		}

		/// <summary>
		/// Sets Bit 1 to 1 and all other to 0, assigning 'x' to this GF2Polynomial.
		/// </summary>
		public virtual void assignX()
		{
			int i;
			for (i = 1; i < blocks; i++)
			{
				value[i] = 0x00;
			}
			value[0] = 0x02;
		}

		/// <summary>
		/// Sets all Bits to 1.
		/// </summary>
		public virtual void assignAll()
		{
			int i;
			for (i = 0; i < blocks; i++)
			{
				value[i] = unchecked((int)0xffffffff);
			}
			zeroUnusedBits();
		}

		/// <summary>
		/// Resets all bits to zero.
		/// </summary>
		public virtual void assignZero()
		{
			int i;
			for (i = 0; i < blocks; i++)
			{
				value[i] = 0x00;
			}
		}

		/// <summary>
		/// Fills all len bits of this GF2Polynomial with random values.
		/// </summary>
		public virtual void randomize()
		{
			int i;
			for (i = 0; i < blocks; i++)
			{
				value[i] = rand.nextInt();
			}
			zeroUnusedBits();
		}

		/// <summary>
		/// Fills all len bits of this GF2Polynomial with random values using the
		/// specified source of randomness.
		/// </summary>
		/// <param name="rand"> the source of randomness </param>
		public virtual void randomize(Random rand)
		{
			int i;
			for (i = 0; i < blocks; i++)
			{
				value[i] = rand.nextInt();
			}
			zeroUnusedBits();
		}

		/// <summary>
		/// Returns true if two GF2Polynomials have the same size and value and thus
		/// are equal.
		/// </summary>
		/// <param name="other"> the other GF2Polynomial </param>
		/// <returns> true if this GF2Polynomial equals <i>b</i> (<i>this</i> ==
		///         <i>b</i>) </returns>
		public override bool Equals(object other)
		{
			if (other == null || !(other is GF2Polynomial))
			{
				return false;
			}

			GF2Polynomial otherPol = (GF2Polynomial)other;

			if (len != otherPol.len)
			{
				return false;
			}
			for (int i = 0; i < blocks; i++)
			{
				if (value[i] != otherPol.value[i])
				{
					return false;
				}
			}
			return true;
		}

		/// <returns> the hash code of this polynomial </returns>
		public override int GetHashCode()
		{
			return len + Arrays.GetHashCode(value);
		}

		/// <summary>
		/// Tests if all bits equal zero.
		/// </summary>
		/// <returns> true if this GF2Polynomial equals 'zero' (<i>this</i> == 0) </returns>
		public virtual bool isZero()
		{
			int i;
			if (len == 0)
			{
				return true;
			}
			for (i = 0; i < blocks; i++)
			{
				if (value[i] != 0)
				{
					return false;
				}
			}
			return true;
		}

		/// <summary>
		/// Tests if all bits are reset to 0 and LSB is set to 1.
		/// </summary>
		/// <returns> true if this GF2Polynomial equals 'one' (<i>this</i> == 1) </returns>
		public virtual bool isOne()
		{
			int i;
			for (i = 1; i < blocks; i++)
			{
				if (value[i] != 0)
				{
					return false;
				}
			}
			if (value[0] != 0x01)
			{
				return false;
			}
			return true;
		}

		/// <summary>
		/// Adds <i>b</i> to this GF2Polynomial and assigns the result to this
		/// GF2Polynomial. <i>b</i> can be of different size.
		/// </summary>
		/// <param name="b"> GF2Polynomial to add to this GF2Polynomial </param>
		public virtual void addToThis(GF2Polynomial b)
		{
			expandN(b.len);
			xorThisBy(b);
		}

		/// <summary>
		/// Adds two GF2Polynomials, <i>this</i> and <i>b</i>, and returns the
		/// result. <i>this</i> and <i>b</i> can be of different size.
		/// </summary>
		/// <param name="b"> a GF2Polynomial </param>
		/// <returns> a new GF2Polynomial (<i>this</i> + <i>b</i>) </returns>
		public virtual GF2Polynomial add(GF2Polynomial b)
		{
			return xor(b);
		}

		/// <summary>
		/// Subtracts <i>b</i> from this GF2Polynomial and assigns the result to
		/// this GF2Polynomial. <i>b</i> can be of different size.
		/// </summary>
		/// <param name="b"> a GF2Polynomial </param>
		public virtual void subtractFromThis(GF2Polynomial b)
		{
			expandN(b.len);
			xorThisBy(b);
		}

		/// <summary>
		/// Subtracts two GF2Polynomials, <i>this</i> and <i>b</i>, and returns the
		/// result in a new GF2Polynomial. <i>this</i> and <i>b</i> can be of
		/// different size.
		/// </summary>
		/// <param name="b"> a GF2Polynomial </param>
		/// <returns> a new GF2Polynomial (<i>this</i> - <i>b</i>) </returns>
		public virtual GF2Polynomial subtract(GF2Polynomial b)
		{
			return xor(b);
		}

		/// <summary>
		/// Toggles the LSB of this GF2Polynomial, increasing its value by 'one'.
		/// </summary>
		public virtual void increaseThis()
		{
			xorBit(0);
		}

		/// <summary>
		/// Toggles the LSB of this GF2Polynomial, increasing the value by 'one' and
		/// returns the result in a new GF2Polynomial.
		/// </summary>
		/// <returns> <tt>this + 1</tt> </returns>
		public virtual GF2Polynomial increase()
		{
			GF2Polynomial result = new GF2Polynomial(this);
			result.increaseThis();
			return result;
		}

		/// <summary>
		/// Multiplies this GF2Polynomial with <i>b</i> and returns the result in a
		/// new GF2Polynomial. This method does not reduce the result in GF(2^N).
		/// This method uses classic multiplication (schoolbook).
		/// </summary>
		/// <param name="b"> a GF2Polynomial </param>
		/// <returns> a new GF2Polynomial (<i>this</i> * <i>b</i>) </returns>
		public virtual GF2Polynomial multiplyClassic(GF2Polynomial b)
		{
			GF2Polynomial result = new GF2Polynomial(Math.Max(len, b.len) << 1);
			GF2Polynomial[] m = new GF2Polynomial[32];
			int i, j;
			m[0] = new GF2Polynomial(this);
			for (i = 1; i <= 31; i++)
			{
				m[i] = m[i - 1].shiftLeft();
			}
			for (i = 0; i < b.blocks; i++)
			{
				for (j = 0; j <= 31; j++)
				{
					if ((b.value[i] & bitMask[j]) != 0)
					{
						result.xorThisBy(m[j]);
					}
				}
				for (j = 0; j <= 31; j++)
				{
					m[j].shiftBlocksLeft();
				}
			}
			return result;
		}

		/// <summary>
		/// Multiplies this GF2Polynomial with <i>b</i> and returns the result in a
		/// new GF2Polynomial. This method does not reduce the result in GF(2^N).
		/// This method uses Karatzuba multiplication.
		/// </summary>
		/// <param name="b"> a GF2Polynomial </param>
		/// <returns> a new GF2Polynomial (<i>this</i> * <i>b</i>) </returns>
		public virtual GF2Polynomial multiply(GF2Polynomial b)
		{
			int n = Math.Max(len, b.len);
			expandN(n);
			b.expandN(n);
			return karaMult(b);
		}

		/// <summary>
		/// Does the recursion for Karatzuba multiplication.
		/// </summary>
		private GF2Polynomial karaMult(GF2Polynomial b)
		{
			GF2Polynomial result = new GF2Polynomial(len << 1);
			if (len <= 32)
			{
				result.value = mult32(value[0], b.value[0]);
				return result;
			}
			if (len <= 64)
			{
				result.value = mult64(value, b.value);
				return result;
			}
			if (len <= 128)
			{
				result.value = mult128(value, b.value);
				return result;
			}
			if (len <= 256)
			{
				result.value = mult256(value, b.value);
				return result;
			}
			if (len <= 512)
			{
				result.value = mult512(value, b.value);
				return result;
			}

			int n = IntegerFunctions.floorLog(len - 1);
			n = bitMask[n];

			GF2Polynomial a0 = lower(((n - 1) >> 5) + 1);
			GF2Polynomial a1 = upper(((n - 1) >> 5) + 1);
			GF2Polynomial b0 = b.lower(((n - 1) >> 5) + 1);
			GF2Polynomial b1 = b.upper(((n - 1) >> 5) + 1);

			GF2Polynomial c = a1.karaMult(b1); // c = a1*b1
			GF2Polynomial e = a0.karaMult(b0); // e = a0*b0
			a0.addToThis(a1); // a0 = a0 + a1
			b0.addToThis(b1); // b0 = b0 + b1
			GF2Polynomial d = a0.karaMult(b0); // d = (a0+a1)*(b0+b1)

			result.shiftLeftAddThis(c, n << 1);
			result.shiftLeftAddThis(c, n);
			result.shiftLeftAddThis(d, n);
			result.shiftLeftAddThis(e, n);
			result.addToThis(e);
			return result;
		}

		/// <summary>
		/// 16-Integer Version of Karatzuba multiplication.
		/// </summary>
		private static int[] mult512(int[] a, int[] b)
		{
			int[] result = new int[32];
			int[] a0 = new int[8];
			JavaSystem.arraycopy(a, 0, a0, 0, Math.Min(8, a.Length));
			int[] a1 = new int[8];
			if (a.Length > 8)
			{
				JavaSystem.arraycopy(a, 8, a1, 0, Math.Min(8, a.Length - 8));
			}
			int[] b0 = new int[8];
			JavaSystem.arraycopy(b, 0, b0, 0, Math.Min(8, b.Length));
			int[] b1 = new int[8];
			if (b.Length > 8)
			{
				JavaSystem.arraycopy(b, 8, b1, 0, Math.Min(8, b.Length - 8));
			}
			int[] c = mult256(a1, b1);
			result[31] ^= c[15];
			result[30] ^= c[14];
			result[29] ^= c[13];
			result[28] ^= c[12];
			result[27] ^= c[11];
			result[26] ^= c[10];
			result[25] ^= c[9];
			result[24] ^= c[8];
			result[23] ^= c[7] ^ c[15];
			result[22] ^= c[6] ^ c[14];
			result[21] ^= c[5] ^ c[13];
			result[20] ^= c[4] ^ c[12];
			result[19] ^= c[3] ^ c[11];
			result[18] ^= c[2] ^ c[10];
			result[17] ^= c[1] ^ c[9];
			result[16] ^= c[0] ^ c[8];
			result[15] ^= c[7];
			result[14] ^= c[6];
			result[13] ^= c[5];
			result[12] ^= c[4];
			result[11] ^= c[3];
			result[10] ^= c[2];
			result[9] ^= c[1];
			result[8] ^= c[0];
			a1[0] ^= a0[0];
			a1[1] ^= a0[1];
			a1[2] ^= a0[2];
			a1[3] ^= a0[3];
			a1[4] ^= a0[4];
			a1[5] ^= a0[5];
			a1[6] ^= a0[6];
			a1[7] ^= a0[7];
			b1[0] ^= b0[0];
			b1[1] ^= b0[1];
			b1[2] ^= b0[2];
			b1[3] ^= b0[3];
			b1[4] ^= b0[4];
			b1[5] ^= b0[5];
			b1[6] ^= b0[6];
			b1[7] ^= b0[7];
			int[] d = mult256(a1, b1);
			result[23] ^= d[15];
			result[22] ^= d[14];
			result[21] ^= d[13];
			result[20] ^= d[12];
			result[19] ^= d[11];
			result[18] ^= d[10];
			result[17] ^= d[9];
			result[16] ^= d[8];
			result[15] ^= d[7];
			result[14] ^= d[6];
			result[13] ^= d[5];
			result[12] ^= d[4];
			result[11] ^= d[3];
			result[10] ^= d[2];
			result[9] ^= d[1];
			result[8] ^= d[0];
			int[] e = mult256(a0, b0);
			result[23] ^= e[15];
			result[22] ^= e[14];
			result[21] ^= e[13];
			result[20] ^= e[12];
			result[19] ^= e[11];
			result[18] ^= e[10];
			result[17] ^= e[9];
			result[16] ^= e[8];
			result[15] ^= e[7] ^ e[15];
			result[14] ^= e[6] ^ e[14];
			result[13] ^= e[5] ^ e[13];
			result[12] ^= e[4] ^ e[12];
			result[11] ^= e[3] ^ e[11];
			result[10] ^= e[2] ^ e[10];
			result[9] ^= e[1] ^ e[9];
			result[8] ^= e[0] ^ e[8];
			result[7] ^= e[7];
			result[6] ^= e[6];
			result[5] ^= e[5];
			result[4] ^= e[4];
			result[3] ^= e[3];
			result[2] ^= e[2];
			result[1] ^= e[1];
			result[0] ^= e[0];
			return result;
		}

		/// <summary>
		/// 8-Integer Version of Karatzuba multiplication.
		/// </summary>
		private static int[] mult256(int[] a, int[] b)
		{
			int[] result = new int[16];
			int[] a0 = new int[4];
			JavaSystem.arraycopy(a, 0, a0, 0, Math.Min(4, a.Length));
			int[] a1 = new int[4];
			if (a.Length > 4)
			{
				JavaSystem.arraycopy(a, 4, a1, 0, Math.Min(4, a.Length - 4));
			}
			int[] b0 = new int[4];
			JavaSystem.arraycopy(b, 0, b0, 0, Math.Min(4, b.Length));
			int[] b1 = new int[4];
			if (b.Length > 4)
			{
				JavaSystem.arraycopy(b, 4, b1, 0, Math.Min(4, b.Length - 4));
			}
			if (a1[3] == 0 && a1[2] == 0 && b1[3] == 0 && b1[2] == 0)
			{
				if (a1[1] == 0 && b1[1] == 0)
				{
					if (a1[0] != 0 || b1[0] != 0)
					{ // [3]=[2]=[1]=0, [0]!=0
						int[] c = mult32(a1[0], b1[0]);
						result[9] ^= c[1];
						result[8] ^= c[0];
						result[5] ^= c[1];
						result[4] ^= c[0];
					}
				}
				else
				{ // [3]=[2]=0 [1]!=0, [0]!=0
					int[] c = mult64(a1, b1);
					result[11] ^= c[3];
					result[10] ^= c[2];
					result[9] ^= c[1];
					result[8] ^= c[0];
					result[7] ^= c[3];
					result[6] ^= c[2];
					result[5] ^= c[1];
					result[4] ^= c[0];
				}
			}
			else
			{ // [3]!=0 [2]!=0 [1]!=0, [0]!=0
				int[] c = mult128(a1, b1);
				result[15] ^= c[7];
				result[14] ^= c[6];
				result[13] ^= c[5];
				result[12] ^= c[4];
				result[11] ^= c[3] ^ c[7];
				result[10] ^= c[2] ^ c[6];
				result[9] ^= c[1] ^ c[5];
				result[8] ^= c[0] ^ c[4];
				result[7] ^= c[3];
				result[6] ^= c[2];
				result[5] ^= c[1];
				result[4] ^= c[0];
			}
			a1[0] ^= a0[0];
			a1[1] ^= a0[1];
			a1[2] ^= a0[2];
			a1[3] ^= a0[3];
			b1[0] ^= b0[0];
			b1[1] ^= b0[1];
			b1[2] ^= b0[2];
			b1[3] ^= b0[3];
			int[] d = mult128(a1, b1);
			result[11] ^= d[7];
			result[10] ^= d[6];
			result[9] ^= d[5];
			result[8] ^= d[4];
			result[7] ^= d[3];
			result[6] ^= d[2];
			result[5] ^= d[1];
			result[4] ^= d[0];
			int[] e = mult128(a0, b0);
			result[11] ^= e[7];
			result[10] ^= e[6];
			result[9] ^= e[5];
			result[8] ^= e[4];
			result[7] ^= e[3] ^ e[7];
			result[6] ^= e[2] ^ e[6];
			result[5] ^= e[1] ^ e[5];
			result[4] ^= e[0] ^ e[4];
			result[3] ^= e[3];
			result[2] ^= e[2];
			result[1] ^= e[1];
			result[0] ^= e[0];
			return result;
		}

		/// <summary>
		/// 4-Integer Version of Karatzuba multiplication.
		/// </summary>
		private static int[] mult128(int[] a, int[] b)
		{
			int[] result = new int[8];
			int[] a0 = new int[2];
			JavaSystem.arraycopy(a, 0, a0, 0, Math.Min(2, a.Length));
			int[] a1 = new int[2];
			if (a.Length > 2)
			{
				JavaSystem.arraycopy(a, 2, a1, 0, Math.Min(2, a.Length - 2));
			}
			int[] b0 = new int[2];
			JavaSystem.arraycopy(b, 0, b0, 0, Math.Min(2, b.Length));
			int[] b1 = new int[2];
			if (b.Length > 2)
			{
				JavaSystem.arraycopy(b, 2, b1, 0, Math.Min(2, b.Length - 2));
			}
			if (a1[1] == 0 && b1[1] == 0)
			{
				if (a1[0] != 0 || b1[0] != 0)
				{
					int[] c = mult32(a1[0], b1[0]);
					result[5] ^= c[1];
					result[4] ^= c[0];
					result[3] ^= c[1];
					result[2] ^= c[0];
				}
			}
			else
			{
				int[] c = mult64(a1, b1);
				result[7] ^= c[3];
				result[6] ^= c[2];
				result[5] ^= c[1] ^ c[3];
				result[4] ^= c[0] ^ c[2];
				result[3] ^= c[1];
				result[2] ^= c[0];
			}
			a1[0] ^= a0[0];
			a1[1] ^= a0[1];
			b1[0] ^= b0[0];
			b1[1] ^= b0[1];
			if (a1[1] == 0 && b1[1] == 0)
			{
				int[] d = mult32(a1[0], b1[0]);
				result[3] ^= d[1];
				result[2] ^= d[0];
			}
			else
			{
				int[] d = mult64(a1, b1);
				result[5] ^= d[3];
				result[4] ^= d[2];
				result[3] ^= d[1];
				result[2] ^= d[0];
			}
			if (a0[1] == 0 && b0[1] == 0)
			{
				int[] e = mult32(a0[0], b0[0]);
				result[3] ^= e[1];
				result[2] ^= e[0];
				result[1] ^= e[1];
				result[0] ^= e[0];
			}
			else
			{
				int[] e = mult64(a0, b0);
				result[5] ^= e[3];
				result[4] ^= e[2];
				result[3] ^= e[1] ^ e[3];
				result[2] ^= e[0] ^ e[2];
				result[1] ^= e[1];
				result[0] ^= e[0];
			}
			return result;
		}

		/// <summary>
		/// 2-Integer Version of Karatzuba multiplication.
		/// </summary>
		private static int[] mult64(int[] a, int[] b)
		{
			int[] result = new int[4];
			int a0 = a[0];
			int a1 = 0;
			if (a.Length > 1)
			{
				a1 = a[1];
			}
			int b0 = b[0];
			int b1 = 0;
			if (b.Length > 1)
			{
				b1 = b[1];
			}
			if (a1 != 0 || b1 != 0)
			{
				int[] c = mult32(a1, b1);
				result[3] ^= c[1];
				result[2] ^= c[0] ^ c[1];
				result[1] ^= c[0];
			}
			int[] d = mult32(a0 ^ a1, b0 ^ b1);
			result[2] ^= d[1];
			result[1] ^= d[0];
			int[] e = mult32(a0, b0);
			result[2] ^= e[1];
			result[1] ^= e[0] ^ e[1];
			result[0] ^= e[0];
			return result;
		}

		/// <summary>
		/// 4-Byte Version of Karatzuba multiplication. Here the actual work is done.
		/// </summary>
		private static int[] mult32(int a, int b)
		{
			int[] result = new int[2];
			if (a == 0 || b == 0)
			{
				return result;
			}
			long b2 = b;
			b2 &= 0x00000000ffffffffL;
			int i;
			long h = 0;
			for (i = 1; i <= 32; i++)
			{
				if ((a & bitMask[i - 1]) != 0)
				{
					h ^= b2;
				}
				b2 <<= 1;
			}
			result[1] = (int)((long)((ulong)h >> 32));
			result[0] = unchecked((int)(h & 0x00000000ffffffffL));
			return result;
		}

		/// <summary>
		/// Returns a new GF2Polynomial containing the upper <i>k</i> bytes of this
		/// GF2Polynomial.
		/// </summary>
		/// <param name="k"> </param>
		/// <returns> a new GF2Polynomial containing the upper <i>k</i> bytes of this
		///         GF2Polynomial </returns>
		/// <seealso cref= GF2Polynomial#karaMult </seealso>
		private GF2Polynomial upper(int k)
		{
			int j = Math.Min(k, blocks - k);
			GF2Polynomial result = new GF2Polynomial(j << 5);
			if (blocks >= k)
			{
				JavaSystem.arraycopy(value, k, result.value, 0, j);
			}
			return result;
		}

		/// <summary>
		/// Returns a new GF2Polynomial containing the lower <i>k</i> bytes of this
		/// GF2Polynomial.
		/// </summary>
		/// <param name="k"> </param>
		/// <returns> a new GF2Polynomial containing the lower <i>k</i> bytes of this
		///         GF2Polynomial </returns>
		/// <seealso cref= GF2Polynomial#karaMult </seealso>
		private GF2Polynomial lower(int k)
		{
			GF2Polynomial result = new GF2Polynomial(k << 5);
			JavaSystem.arraycopy(value, 0, result.value, 0, Math.Min(k, blocks));
			return result;
		}

		/// <summary>
		/// Returns the remainder of <i>this</i> divided by <i>g</i> in a new
		/// GF2Polynomial.
		/// </summary>
		/// <param name="g"> GF2Polynomial != 0 </param>
		/// <returns> a new GF2Polynomial (<i>this</i> % <i>g</i>) </returns>
		public virtual GF2Polynomial remainder(GF2Polynomial g)
		{
			/* a div b = q / r */
			GF2Polynomial a = new GF2Polynomial(this);
			GF2Polynomial b = new GF2Polynomial(g);
			GF2Polynomial j;
			int i;
			if (b.isZero())
			{
				throw new RuntimeException();
			}
			a.reduceN();
			b.reduceN();
			if (a.len < b.len)
			{
				return a;
			}
			i = a.len - b.len;
			while (i >= 0)
			{
				j = b.shiftLeft(i);
				a.subtractFromThis(j);
				a.reduceN();
				i = a.len - b.len;
			}
			return a;
		}

		/// <summary>
		/// Returns the absolute quotient of <i>this</i> divided by <i>g</i> in a
		/// new GF2Polynomial.
		/// </summary>
		/// <param name="g"> GF2Polynomial != 0 </param>
		/// <returns> a new GF2Polynomial |_ <i>this</i> / <i>g</i> _| </returns>
		public virtual GF2Polynomial quotient(GF2Polynomial g)
		{
			/* a div b = q / r */
			GF2Polynomial q = new GF2Polynomial(len);
			GF2Polynomial a = new GF2Polynomial(this);
			GF2Polynomial b = new GF2Polynomial(g);
			GF2Polynomial j;
			int i;
			if (b.isZero())
			{
				throw new RuntimeException();
			}
			a.reduceN();
			b.reduceN();
			if (a.len < b.len)
			{
				return new GF2Polynomial(0);
			}
			i = a.len - b.len;
			q.expandN(i + 1);

			while (i >= 0)
			{
				j = b.shiftLeft(i);
				a.subtractFromThis(j);
				a.reduceN();
				q.xorBit(i);
				i = a.len - b.len;
			}

			return q;
		}

		/// <summary>
		/// Divides <i>this</i> by <i>g</i> and returns the quotient and remainder
		/// in a new GF2Polynomial[2], quotient in [0], remainder in [1].
		/// </summary>
		/// <param name="g"> GF2Polynomial != 0 </param>
		/// <returns> a new GF2Polynomial[2] containing quotient and remainder </returns>
		public virtual GF2Polynomial[] divide(GF2Polynomial g)
		{
			/* a div b = q / r */
			GF2Polynomial[] result = new GF2Polynomial[2];
			GF2Polynomial q = new GF2Polynomial(len);
			GF2Polynomial a = new GF2Polynomial(this);
			GF2Polynomial b = new GF2Polynomial(g);
			GF2Polynomial j;
			int i;
			if (b.isZero())
			{
				throw new RuntimeException();
			}
			a.reduceN();
			b.reduceN();
			if (a.len < b.len)
			{
				result[0] = new GF2Polynomial(0);
				result[1] = a;
				return result;
			}
			i = a.len - b.len;
			q.expandN(i + 1);

			while (i >= 0)
			{
				j = b.shiftLeft(i);
				a.subtractFromThis(j);
				a.reduceN();
				q.xorBit(i);
				i = a.len - b.len;
			}

			result[0] = q;
			result[1] = a;
			return result;
		}

		/// <summary>
		/// Returns the greatest common divisor of <i>this</i> and <i>g</i> in a
		/// new GF2Polynomial.
		/// </summary>
		/// <param name="g"> GF2Polynomial != 0 </param>
		/// <returns> a new GF2Polynomial gcd(<i>this</i>,<i>g</i>) </returns>
		/// <exception cref="ArithmeticException"> if <i>this</i> and <i>g</i> both are equal to zero </exception>
		public virtual GF2Polynomial gcd(GF2Polynomial g)
		{
			if (isZero() && g.isZero())
			{
				throw new ArithmeticException("Both operands of gcd equal zero.");
			}
			if (isZero())
			{
				return new GF2Polynomial(g);
			}
			if (g.isZero())
			{
				return new GF2Polynomial(this);
			}
			GF2Polynomial a = new GF2Polynomial(this);
			GF2Polynomial b = new GF2Polynomial(g);
			GF2Polynomial c;

			while (!b.isZero())
			{
				c = a.remainder(b);
				a = b;
				b = c;
			}

			return a;
		}

		/// <summary>
		/// Checks if <i>this</i> is irreducible, according to IEEE P1363, A.5.5,
		/// p103.<br>
		/// Note: The algorithm from IEEE P1363, A5.5 can be used to check a
		/// polynomial with coefficients in GF(2^r) for irreducibility. As this class
		/// only represents polynomials with coefficients in GF(2), the algorithm is
		/// adapted to the case r=1.
		/// </summary>
		/// <returns> true if <i>this</i> is irreducible </returns>
		/// <seealso cref= "P1363, A.5.5, p103" </seealso>
		public virtual bool isIrreducible()
		{
			if (isZero())
			{
				return false;
			}
			GF2Polynomial f = new GF2Polynomial(this);
			int d, i;
			GF2Polynomial u, g;
			GF2Polynomial dummy;
			f.reduceN();
			d = f.len - 1;
			u = new GF2Polynomial(f.len, "X");

			for (i = 1; i <= (d >> 1); i++)
			{
				u.squareThisPreCalc();
				u = u.remainder(f);
				dummy = u.add(new GF2Polynomial(32, "X"));
				if (!dummy.isZero())
				{
					g = f.gcd(dummy);
					if (!g.isOne())
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}

			return true;
		}

		/// <summary>
		/// Reduces this GF2Polynomial using the trinomial x^<i>m</i> + x^<i>tc</i> +
		/// 1.
		/// </summary>
		/// <param name="m">  the degree of the used field </param>
		/// <param name="tc"> degree of the middle x in the trinomial </param>
		public virtual void reduceTrinomial(int m, int tc)
		{
			int i;
			int p0, p1;
			int q0, q1;
			long t;
			p0 = (int)((uint)m >> 5); // block which contains 2^m
			q0 = 32 - (m & 0x1f); // (32-index) of 2^m within block p0
			p1 = (int)((uint)(m - tc) >> 5); // block which contains 2^tc
			q1 = 32 - ((m - tc) & 0x1f); // (32-index) of 2^tc within block q1
			int max = (int)((uint)((m << 1) - 2) >> 5); // block which contains 2^(2m-2)
			int min = p0; // block which contains 2^m
			for (i = max; i > min; i--)
			{ // for i = maxBlock to minBlock
				// reduce coefficients contained in t
				// t = block[i]
				t = value[i] & 0x00000000ffffffffL;
				// block[i-p0-1] ^= t << q0
				value[i - p0 - 1] ^= (int)(t << q0);
				// block[i-p0] ^= t >>> (32-q0)
				value[i - p0] ^= (int)((long)((ulong)t >> (32 - q0)));
				// block[i-p1-1] ^= << q1
				value[i - p1 - 1] ^= (int)(t << q1);
				// block[i-p1] ^= t >>> (32-q1)
				value[i - p1] ^= (int)((long)((ulong)t >> (32 - q1)));
				value[i] = 0x00;
			}
			// reduce last coefficients in block containing 2^m
			t = value[min] & 0x00000000ffffffffL & (0xffffffffL << (m & 0x1f)); // t
			// contains the last coefficients > m
			value[0] ^= (int)((long)((ulong)t >> (32 - q0)));
			if (min - p1 - 1 >= 0)
			{
				value[min - p1 - 1] ^= (int)(t << q1);
			}
			value[min - p1] ^= (int)((long)((ulong)t >> (32 - q1)));

			value[min] &= reverseRightMask[m & 0x1f];
			blocks = ((int)((uint)(m - 1) >> 5)) + 1;
			len = m;
		}

		/// <summary>
		/// Reduces this GF2Polynomial using the pentanomial x^<i>m</i> + x^<i>pc[2]</i> +
		/// x^<i>pc[1]</i> + x^<i>pc[0]</i> + 1.
		/// </summary>
		/// <param name="m">  the degree of the used field </param>
		/// <param name="pc"> degrees of the middle x's in the pentanomial </param>
		public virtual void reducePentanomial(int m, int[] pc)
		{
			int i;
			int p0, p1, p2, p3;
			int q0, q1, q2, q3;
			long t;
			p0 = (int)((uint)m >> 5);
			q0 = 32 - (m & 0x1f);
			p1 = (int)((uint)(m - pc[0]) >> 5);
			q1 = 32 - ((m - pc[0]) & 0x1f);
			p2 = (int)((uint)(m - pc[1]) >> 5);
			q2 = 32 - ((m - pc[1]) & 0x1f);
			p3 = (int)((uint)(m - pc[2]) >> 5);
			q3 = 32 - ((m - pc[2]) & 0x1f);
			int max = (int)((uint)((m << 1) - 2) >> 5);
			int min = p0;
			for (i = max; i > min; i--)
			{
				t = value[i] & 0x00000000ffffffffL;
				value[i - p0 - 1] ^= (int)(t << q0);
				value[i - p0] ^= (int)((long)((ulong)t >> (32 - q0)));
				value[i - p1 - 1] ^= (int)(t << q1);
				value[i - p1] ^= (int)((long)((ulong)t >> (32 - q1)));
				value[i - p2 - 1] ^= (int)(t << q2);
				value[i - p2] ^= (int)((long)((ulong)t >> (32 - q2)));
				value[i - p3 - 1] ^= (int)(t << q3);
				value[i - p3] ^= (int)((long)((ulong)t >> (32 - q3)));
				value[i] = 0;
			}
			t = value[min] & 0x00000000ffffffffL & (0xffffffffL << (m & 0x1f));
			value[0] ^= (int)((long)((ulong)t >> (32 - q0)));
			if (min - p1 - 1 >= 0)
			{
				value[min - p1 - 1] ^= (int)(t << q1);
			}
			value[min - p1] ^= (int)((long)((ulong)t >> (32 - q1)));
			if (min - p2 - 1 >= 0)
			{
				value[min - p2 - 1] ^= (int)(t << q2);
			}
			value[min - p2] ^= (int)((long)((ulong)t >> (32 - q2)));
			if (min - p3 - 1 >= 0)
			{
				value[min - p3 - 1] ^= (int)(t << q3);
			}
			value[min - p3] ^= (int)((long)((ulong)t >> (32 - q3)));
			value[min] &= reverseRightMask[m & 0x1f];

			blocks = ((int)((uint)(m - 1) >> 5)) + 1;
			len = m;
		}

		/// <summary>
		/// Reduces len by finding the most significant bit set to one and reducing
		/// len and blocks.
		/// </summary>
		public virtual void reduceN()
		{
			int i, j, h;
			i = blocks - 1;
			while ((value[i] == 0) && (i > 0))
			{
				i--;
			}
			h = value[i];
			j = 0;
			while (h != 0)
			{
				h = (int)((uint)h >> 1);
				j++;
			}
			len = (i << 5) + j;
			blocks = i + 1;
		}

		/// <summary>
		/// Expands len and int[] value to <i>i</i>. This is useful before adding
		/// two GF2Polynomials of different size.
		/// </summary>
		/// <param name="i"> the intended length </param>
		public virtual void expandN(int i)
		{
			int k;
			int[] bs;
			if (len >= i)
			{
				return;
			}
			len = i;
			k = ((int)((uint)(i - 1) >> 5)) + 1;
			if (blocks >= k)
			{
				return;
			}
			if (value.Length >= k)
			{
				int j;
				for (j = blocks; j < k; j++)
				{
					value[j] = 0;
				}
				blocks = k;
				return;
			}
			bs = new int[k];
			JavaSystem.arraycopy(value, 0, bs, 0, blocks);
			blocks = k;
			value = null;
			value = bs;
		}

		/// <summary>
		/// Squares this GF2Polynomial and expands it accordingly. This method does
		/// not reduce the result in GF(2^N). There exists a faster method for
		/// squaring in GF(2^N).
		/// </summary>
		/// <seealso cref= GF2nPolynomialElement#square </seealso>
		public virtual void squareThisBitwise()
		{
			int i, h, j, k;
			if (isZero())
			{
				return;
			}
			int[] result = new int[blocks << 1];
			for (i = blocks - 1; i >= 0; i--)
			{
				h = value[i];
				j = 0x00000001;
				for (k = 0; k < 16; k++)
				{
					if ((h & 0x01) != 0)
					{
						result[i << 1] |= j;
					}
					if ((h & 0x00010000) != 0)
					{
						result[(i << 1) + 1] |= j;
					}
					j <<= 2;
					h = (int)((uint)h >> 1);
				}
			}
			value = null;
			value = result;
			blocks = result.Length;
			len = (len << 1) - 1;
		}

		/// <summary>
		/// Squares this GF2Polynomial by using precomputed values of squaringTable.
		/// This method does not reduce the result in GF(2^N).
		/// </summary>
		public virtual void squareThisPreCalc()
		{
			int i;
			if (isZero())
			{
				return;
			}
			if (value.Length >= (blocks << 1))
			{
				for (i = blocks - 1; i >= 0; i--)
				{
					value[(i << 1) + 1] = GF2Polynomial.squaringTable[(int)((uint)(value[i] & 0x00ff0000) >> 16)] | (GF2Polynomial.squaringTable[(long)((ulong)(value[i] & 0xff000000) >> 24)] << 16);
					value[i << 1] = GF2Polynomial.squaringTable[value[i] & 0x000000ff] | (GF2Polynomial.squaringTable[(int)((uint)(value[i] & 0x0000ff00) >> 8)] << 16);
				}
				blocks <<= 1;
				len = (len << 1) - 1;
			}
			else
			{
				int[] result = new int[blocks << 1];
				for (i = 0; i < blocks; i++)
				{
					result[i << 1] = GF2Polynomial.squaringTable[value[i] & 0x000000ff] | (GF2Polynomial.squaringTable[(int)((uint)(value[i] & 0x0000ff00) >> 8)] << 16);
					result[(i << 1) + 1] = GF2Polynomial.squaringTable[(int)((uint)(value[i] & 0x00ff0000) >> 16)] | (GF2Polynomial.squaringTable[(long)((ulong)(value[i] & 0xff000000) >> 24)] << 16);
				}
				value = null;
				value = result;
				blocks <<= 1;
				len = (len << 1) - 1;
			}
		}

		/// <summary>
		/// Does a vector-multiplication modulo 2 and returns the result as boolean.
		/// </summary>
		/// <param name="b"> GF2Polynomial </param>
		/// <returns> this x <i>b</i> as boolean (1-&gt;true, 0-&gt;false) </returns>
		public virtual bool vectorMult(GF2Polynomial b)
		{
			int i;
			int h;
			bool result = false;
			if (len != b.len)
			{
				throw new RuntimeException();
			}
			for (i = 0; i < blocks; i++)
			{
				h = value[i] & b.value[i];
				result ^= parity[h & 0x000000ff];
				result ^= parity[((int)((uint)h >> 8)) & 0x000000ff];
				result ^= parity[((int)((uint)h >> 16)) & 0x000000ff];
				result ^= parity[((int)((uint)h >> 24)) & 0x000000ff];
			}
			return result;
		}

		/// <summary>
		/// Returns the bitwise exclusive-or of <i>this</i> and <i>b</i> in a new
		/// GF2Polynomial. <i>this</i> and <i>b</i> can be of different size.
		/// </summary>
		/// <param name="b"> GF2Polynomial </param>
		/// <returns> a new GF2Polynomial (<i>this</i> ^ <i>b</i>) </returns>
		public virtual GF2Polynomial xor(GF2Polynomial b)
		{
			int i;
			GF2Polynomial result;
			int k = Math.Min(blocks, b.blocks);
			if (len >= b.len)
			{
				result = new GF2Polynomial(this);
				for (i = 0; i < k; i++)
				{
					result.value[i] ^= b.value[i];
				}
			}
			else
			{
				result = new GF2Polynomial(b);
				for (i = 0; i < k; i++)
				{
					result.value[i] ^= value[i];
				}
			}
			// If we xor'ed some bits too many by proceeding blockwise,
			// restore them to zero:
			result.zeroUnusedBits();
			return result;
		}

		/// <summary>
		/// Computes the bitwise exclusive-or of this GF2Polynomial and <i>b</i> and
		/// stores the result in this GF2Polynomial. <i>b</i> can be of different
		/// size.
		/// </summary>
		/// <param name="b"> GF2Polynomial </param>
		public virtual void xorThisBy(GF2Polynomial b)
		{
			int i;
			for (i = 0; i < Math.Min(blocks, b.blocks); i++)
			{
				value[i] ^= b.value[i];
			}
			// If we xor'ed some bits too many by proceeding blockwise,
			// restore them to zero:
			zeroUnusedBits();
		}

		/// <summary>
		/// If <seealso cref="#len"/> is not a multiple of the block size (32), some extra bits
		/// of the last block might have been modified during a blockwise operation.
		/// This method compensates for that by restoring these "extra" bits to zero.
		/// </summary>
		private void zeroUnusedBits()
		{
			if ((len & 0x1f) != 0)
			{
				value[blocks - 1] &= reverseRightMask[len & 0x1f];
			}
		}

		/// <summary>
		/// Sets the bit at position <i>i</i>.
		/// </summary>
		/// <param name="i"> int </param>
		/// <exception cref="RuntimeException"> if (<i>i</i> &lt; 0) || (<i>i</i> &gt; (len - 1)) </exception>
		public virtual void setBit(int i)
		{
			if (i < 0 || i > (len - 1))
			{
				throw new RuntimeException();
			}
			value[(int)((uint)i >> 5)] |= bitMask[i & 0x1f];
			return;
		}

		/// <summary>
		/// Returns the bit at position <i>i</i>.
		/// </summary>
		/// <param name="i"> int </param>
		/// <returns> the bit at position <i>i</i> if <i>i</i> is a valid position, 0
		///         otherwise. </returns>
		public virtual int getBit(int i)
		{
			if (i < 0)
			{
				throw new RuntimeException();
			}
			if (i > (len - 1))
			{
				return 0;
			}
			return ((value[(int)((uint)i >> 5)] & bitMask[i & 0x1f]) != 0) ? 1 : 0;
		}

		/// <summary>
		/// Resets the bit at position <i>i</i>.
		/// </summary>
		/// <param name="i"> int </param>
		/// <exception cref="RuntimeException"> if (<i>i</i> &lt; 0) || (<i>i</i> &gt; (len - 1)) </exception>
		public virtual void resetBit(int i)
		{
			if (i < 0)
			{
				throw new RuntimeException();
			}
			if (i > (len - 1))
			{
				return;
			}
			value[(int)((uint)i >> 5)] &= ~bitMask[i & 0x1f];
		}

		/// <summary>
		/// Xors the bit at position <i>i</i>.
		/// </summary>
		/// <param name="i"> int </param>
		/// <exception cref="RuntimeException"> if (<i>i</i> &lt; 0) || (<i>i</i> &gt; (len - 1)) </exception>
		public virtual void xorBit(int i)
		{
			if (i < 0 || i > (len - 1))
			{
				throw new RuntimeException();
			}
			value[(int)((uint)i >> 5)] ^= bitMask[i & 0x1f];
		}

		/// <summary>
		/// Tests the bit at position <i>i</i>.
		/// </summary>
		/// <param name="i"> the position of the bit to be tested </param>
		/// <returns> true if the bit at position <i>i</i> is set (a(<i>i</i>) ==
		///         1). False if (<i>i</i> &lt; 0) || (<i>i</i> &gt; (len - 1)) </returns>
		public virtual bool testBit(int i)
		{
			if (i < 0)
			{
				throw new RuntimeException();
			}
			if (i > (len - 1))
			{
				return false;
			}
			return (value[(int)((uint)i >> 5)] & bitMask[i & 0x1f]) != 0;
		}

		/// <summary>
		/// Returns this GF2Polynomial shift-left by 1 in a new GF2Polynomial.
		/// </summary>
		/// <returns> a new GF2Polynomial (this &lt;&lt; 1) </returns>
		public virtual GF2Polynomial shiftLeft()
		{
			GF2Polynomial result = new GF2Polynomial(len + 1, value);
			int i;
			for (i = result.blocks - 1; i >= 1; i--)
			{
				result.value[i] <<= 1;
				result.value[i] |= (int)((uint)result.value[i - 1] >> 31);
			}
			result.value[0] <<= 1;
			return result;
		}

		/// <summary>
		/// Shifts-left this by one and enlarges the size of value if necesary.
		/// </summary>
		public virtual void shiftLeftThis()
		{
			/// <summary>
			/// @todo This is untested. </summary>
			int i;
			if ((len & 0x1f) == 0)
			{ // check if blocks increases
				len += 1;
				blocks += 1;
				if (blocks > value.Length)
				{ // enlarge value
					int[] bs = new int[blocks];
					JavaSystem.arraycopy(value, 0, bs, 0, value.Length);
					value = null;
					value = bs;
				}
				for (i = blocks - 1; i >= 1; i--)
				{
					value[i] |= (int)((uint)value[i - 1] >> 31);
					value[i - 1] <<= 1;
				}
			}
			else
			{
				len += 1;
				for (i = blocks - 1; i >= 1; i--)
				{
					value[i] <<= 1;
					value[i] |= (int)((uint)value[i - 1] >> 31);
				}
				value[0] <<= 1;
			}
		}

		/// <summary>
		/// Returns this GF2Polynomial shift-left by <i>k</i> in a new
		/// GF2Polynomial.
		/// </summary>
		/// <param name="k"> int </param>
		/// <returns> a new GF2Polynomial (this &lt;&lt; <i>k</i>) </returns>
		public virtual GF2Polynomial shiftLeft(int k)
		{
			// Variant 2, requiring a modified shiftBlocksLeft(k)
			// In case of modification, consider a rename to doShiftBlocksLeft()
			// with an explicit note that this method assumes that the polynomial
			// has already been resized. Or consider doing things inline.
			// Construct the resulting polynomial of appropriate length:
			GF2Polynomial result = new GF2Polynomial(len + k, value);
			// Shift left as many multiples of the block size as possible:
			if (k >= 32)
			{
				result.doShiftBlocksLeft((int)((uint)k >> 5));
			}
			// Shift left by the remaining (<32) amount:

			int remaining = k & 0x1f;
			if (remaining != 0)
			{
				for (int i = result.blocks - 1; i >= 1; i--)
				{
					result.value[i] <<= remaining;
					result.value[i] |= (int)((uint)result.value[i - 1] >> (32 - remaining));
				}
				result.value[0] <<= remaining;
			}
			return result;
		}

		/// <summary>
		/// Shifts left b and adds the result to Its a fast version of
		/// <tt>this = add(b.shl(k));</tt>
		/// </summary>
		/// <param name="b"> GF2Polynomial to shift and add to this </param>
		/// <param name="k"> the amount to shift </param>
		/// <seealso cref= GF2nPolynomialElement#invertEEA </seealso>
		public virtual void shiftLeftAddThis(GF2Polynomial b, int k)
		{
			if (k == 0)
			{
				addToThis(b);
				return;
			}
			int i;
			expandN(b.len + k);
			int d = (int)((uint)k >> 5);
			for (i = b.blocks - 1; i >= 0; i--)
			{
				if ((i + d + 1 < blocks) && ((k & 0x1f) != 0))
				{
					value[i + d + 1] ^= (int)((uint)b.value[i] >> (32 - (k & 0x1f)));
				}
				value[i + d] ^= b.value[i] << (k & 0x1f);
			}
		}

		/// <summary>
		/// Shifts-left this GF2Polynomial's value blockwise 1 block resulting in a
		/// shift-left by 32.
		/// </summary>
		/// <seealso cref= GF2Polynomial#multiply </seealso>
		public virtual void shiftBlocksLeft()
		{
			blocks += 1;
			len += 32;
			if (blocks <= value.Length)
			{
				int i;
				for (i = blocks - 1; i >= 1; i--)
				{
					value[i] = value[i - 1];
				}
				value[0] = 0x00;
			}
			else
			{
				int[] result = new int[blocks];
				JavaSystem.arraycopy(value, 0, result, 1, blocks - 1);
				value = null;
				value = result;
			}
		}

		/// <summary>
		/// Shifts left this GF2Polynomial's value blockwise <i>b</i> blocks
		/// resulting in a shift-left by b*32. This method assumes that <seealso cref="#len"/>
		/// and <seealso cref="#blocks"/> have already been updated to reflect the final state.
		/// </summary>
		/// <param name="b"> shift amount (in blocks) </param>
		private void doShiftBlocksLeft(int b)
		{
			if (blocks <= value.Length)
			{
				int i;
				for (i = blocks - 1; i >= b; i--)
				{
					value[i] = value[i - b];
				}
				for (i = 0; i < b; i++)
				{
					value[i] = 0x00;
				}
			}
			else
			{
				int[] result = new int[blocks];
				JavaSystem.arraycopy(value, 0, result, b, blocks - b);
				value = null;
				value = result;
			}
		}

		/// <summary>
		/// Returns this GF2Polynomial shift-right by 1 in a new GF2Polynomial.
		/// </summary>
		/// <returns> a new GF2Polynomial (this &lt;&lt; 1) </returns>
		public virtual GF2Polynomial shiftRight()
		{
			GF2Polynomial result = new GF2Polynomial(len - 1);
			int i;
			JavaSystem.arraycopy(value, 0, result.value, 0, result.blocks);
			for (i = 0; i <= result.blocks - 2; i++)
			{
				result.value[i] = (int)((uint)result.value[i] >> 1);
				result.value[i] |= result.value[i + 1] << 31;
			}
			result.value[result.blocks - 1] = (int)((uint)result.value[result.blocks - 1] >> 1);
			if (result.blocks < blocks)
			{
				result.value[result.blocks - 1] |= value[result.blocks] << 31;
			}
			return result;
		}

		/// <summary>
		/// Shifts-right this GF2Polynomial by 1.
		/// </summary>
		public virtual void shiftRightThis()
		{
			int i;
			len -= 1;
			blocks = ((int)((uint)(len - 1) >> 5)) + 1;
			for (i = 0; i <= blocks - 2; i++)
			{
				value[i] = (int)((uint)value[i] >> 1);
				value[i] |= value[i + 1] << 31;
			}
			value[blocks - 1] = (int)((uint)value[blocks - 1] >> 1);
			if ((len & 0x1f) == 0)
			{
				value[blocks - 1] |= value[blocks] << 31;
			}
		}

	}

}