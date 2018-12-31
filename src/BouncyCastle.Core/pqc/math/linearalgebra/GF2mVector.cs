﻿using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.math.linearalgebra
{

	
	/// <summary>
	/// This class implements vectors over the finite field
	/// <tt>GF(2<sup>m</sup>)</tt> for small <tt>m</tt> (i.e.,
	/// <tt>1&lt;m&lt;32</tt>). It extends the abstract class <seealso cref="Vector"/>.
	/// </summary>
	public class GF2mVector : Vector
	{

		/// <summary>
		/// the finite field this vector is defined over
		/// </summary>
		private GF2mField field;

		/// <summary>
		/// the element array
		/// </summary>
		private int[] vector;

		/// <summary>
		/// creates the vector over GF(2^m) of given length and with elements from
		/// array v (beginning at the first bit)
		/// </summary>
		/// <param name="field"> finite field </param>
		/// <param name="v">     array with elements of vector </param>
		public GF2mVector(GF2mField field, byte[] v)
		{
			this.field = new GF2mField(field);

			// decode vector
			int d = 8;
			int count = 1;
			while (field.getDegree() > d)
			{
				count++;
				d += 8;
			}

			if ((v.Length % count) != 0)
			{
				throw new IllegalArgumentException("Byte array is not an encoded vector over the given finite field.");
			}

			length = v.Length / count;
			vector = new int[length];
			count = 0;
			for (int i = 0; i < vector.Length; i++)
			{
				for (int j = 0; j < d; j += 8)
				{
					vector[i] |= (v[count++] & 0xff) << j;
				}
				if (!field.isElementOfThisField(vector[i]))
				{
					throw new IllegalArgumentException("Byte array is not an encoded vector over the given finite field.");
				}
			}
		}

		/// <summary>
		/// Create a new vector over <tt>GF(2<sup>m</sup>)</tt> of the given
		/// length and element array.
		/// </summary>
		/// <param name="field">  the finite field <tt>GF(2<sup>m</sup>)</tt> </param>
		/// <param name="vector"> the element array </param>
		public GF2mVector(GF2mField field, int[] vector)
		{
			this.field = field;
			length = vector.Length;
			for (int i = vector.Length - 1; i >= 0; i--)
			{
				if (!field.isElementOfThisField(vector[i]))
				{
					throw new ArithmeticException("Element array is not specified over the given finite field.");
				}
			}
			this.vector = IntUtils.clone(vector);
		}

		/// <summary>
		/// Copy constructor.
		/// </summary>
		/// <param name="other"> another <seealso cref="GF2mVector"/> </param>
		public GF2mVector(GF2mVector other)
		{
			field = new GF2mField(other.field);
			length = other.length;
			vector = IntUtils.clone(other.vector);
		}

		/// <returns> the finite field this vector is defined over </returns>
		public virtual GF2mField getField()
		{
			return field;
		}

		/// <returns> int[] form of this vector </returns>
		public virtual int[] getIntArrayForm()
		{
			return IntUtils.clone(vector);
		}

		/// <returns> a byte array encoding of this vector </returns>
		public override byte[] getEncoded()
		{
			int d = 8;
			int count = 1;
			while (field.getDegree() > d)
			{
				count++;
				d += 8;
			}

			byte[] res = new byte[vector.Length * count];
			count = 0;
			for (int i = 0; i < vector.Length; i++)
			{
				for (int j = 0; j < d; j += 8)
				{
					res[count++] = (byte)((int)((uint)vector[i] >> j));
				}
			}

			return res;
		}

		/// <returns> whether this is the zero vector (i.e., all elements are zero) </returns>
		public override bool isZero()
		{
			for (int i = vector.Length - 1; i >= 0; i--)
			{
				if (vector[i] != 0)
				{
					return false;
				}
			}
			return true;
		}

		/// <summary>
		/// Add another vector to this vector. Method is not yet implemented.
		/// </summary>
		/// <param name="addend"> the other vector </param>
		/// <returns> <tt>this + addend</tt> </returns>
		/// <exception cref="ArithmeticException"> if the other vector is not defined over the same field as
		/// this vector.
		/// <para>
		/// TODO: implement this method </exception>
		public override Vector add(Vector addend)
		{
			throw new RuntimeException("not implemented");
		}

		/// <summary>
		/// Multiply this vector with a permutation.
		/// </summary>
		/// <param name="p"> the permutation </param>
		/// <returns> <tt>this*p = p*this</tt> </returns>
		public override Vector multiply(Permutation p)
		{
			int[] pVec = p.getVector();
			if (length != pVec.Length)
			{
				throw new ArithmeticException("permutation size and vector size mismatch");
			}

			int[] result = new int[length];
			for (int i = 0; i < pVec.Length; i++)
			{
				result[i] = vector[pVec[i]];
			}

			return new GF2mVector(field, result);
		}

		/// <summary>
		/// Compare this vector with another object.
		/// </summary>
		/// <param name="other"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object other)
		{

			if (!(other is GF2mVector))
			{
				return false;
			}
			GF2mVector otherVec = (GF2mVector)other;

			if (!field.Equals(otherVec.field))
			{
				return false;
			}

			return IntUtils.Equals(vector, otherVec.vector);
		}

		/// <returns> the hash code of this vector </returns>
		public override int GetHashCode()
		{
			int hash = this.field.GetHashCode();
			hash = hash * 31 + Arrays.GetHashCode(vector);
			return hash;
		}

		/// <returns> a human readable form of this vector </returns>
		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			for (int i = 0; i < vector.Length; i++)
			{
				for (int j = 0; j < field.getDegree(); j++)
				{
					int r = j & 0x1f;
					int bitMask = 1 << r;
					int coeff = vector[i] & bitMask;
					if (coeff != 0)
					{
						buf.append('1');
					}
					else
					{
						buf.append('0');
					}
				}
				buf.append(' ');
			}
			return buf.ToString();
		}

	}

}