using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// Base class for BIT STRING objects
	/// </summary>
	public abstract class ASN1BitString : ASN1Primitive, ASN1String
	{
		private static readonly char[] table = new char[] {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

		protected internal readonly byte[] data;
		protected internal readonly int padBits;

		/// <param name="bitString"> an int containing the BIT STRING </param>
		/// <returns> the correct number of pad bits for a bit string defined in
		/// a 32 bit constant </returns>
		protected internal static int getPadBits(int bitString)
		{
			int val = 0;
			for (int i = 3; i >= 0; i--)
			{
				//
				// this may look a little odd, but if it isn't done like this pre jdk1.2
				// JVM's break!
				//
				if (i != 0)
				{
					if ((bitString >> (i * 8)) != 0)
					{
						val = (bitString >> (i * 8)) & 0xFF;
						break;
					}
				}
				else
				{
					if (bitString != 0)
					{
						val = bitString & 0xFF;
						break;
					}
				}
			}

			if (val == 0)
			{
				return 0;
			}


			int bits = 1;

			while (((val <<= 1) & 0xFF) != 0)
			{
				bits++;
			}

			return 8 - bits;
		}

		/// <param name="bitString"> an int containing the BIT STRING </param>
		/// <returns> the correct number of bytes for a bit string defined in
		/// a 32 bit constant </returns>
		protected internal static byte[] getBytes(int bitString)
		{
			if (bitString == 0)
			{
				return new byte[0];
			}

			int bytes = 4;
			for (int i = 3; i >= 1; i--)
			{
				if ((bitString & (0xFF << (i * 8))) != 0)
				{
					break;
				}
				bytes--;
			}

			byte[] result = new byte[bytes];
			for (int i = 0; i < bytes; i++)
			{
				result[i] = unchecked((byte)((bitString >> (i * 8)) & 0xFF));
			}

			return result;
		}

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="data"> the octets making up the bit string. </param>
		/// <param name="padBits"> the number of extra bits at the end of the string. </param>
		public ASN1BitString(byte[] data, int padBits)
		{
			if (data == null)
			{
				throw new NullPointerException("data cannot be null");
			}
			if (data.Length == 0 && padBits != 0)
			{
				throw new IllegalArgumentException("zero length data with non-zero pad bits");
			}
			if (padBits > 7 || padBits < 0)
			{
				throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
			}

			this.data = Arrays.clone(data);
			this.padBits = padBits;
		}

		/// <summary>
		/// Return a String representation of this BIT STRING
		/// </summary>
		/// <returns> a String representation. </returns>
		public virtual string getString()
		{
			StringBuffer buf = new StringBuffer("#");
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			try
			{
				aOut.writeObject(this);
			}
			catch (IOException e)
			{
				throw new ASN1ParsingException("Internal error encoding BitString: " + e.Message, e);
			}

			byte[] @string = bOut.toByteArray();

			for (int i = 0; i != @string.Length; i++)
			{
				buf.append(table[((int)((uint)@string[i] >> 4)) & 0xf]);
				buf.append(table[@string[i] & 0xf]);
			}

			return buf.ToString();
		}

		/// <returns> the value of the bit string as an int (truncating if necessary) </returns>
		public virtual int intValue()
		{
			int value = 0;
			byte[] @string = data;

			if (padBits > 0 && data.Length <= 4)
			{
				@string = derForm(data, padBits);
			}

			for (int i = 0; i != @string.Length && i != 4; i++)
			{
				value |= (@string[i] & 0xff) << (8 * i);
			}

			return value;
		}

		/// <summary>
		/// Return the octets contained in this BIT STRING, checking that this BIT STRING really
		/// does represent an octet aligned string. Only use this method when the standard you are
		/// following dictates that the BIT STRING will be octet aligned.
		/// </summary>
		/// <returns> a copy of the octet aligned data. </returns>
		public virtual byte[] getOctets()
		{
			if (padBits != 0)
			{
				throw new IllegalStateException("attempt to get non-octet aligned data from BIT STRING");
			}

			return Arrays.clone(data);
		}

		public virtual byte[] getBytes()
		{
			return derForm(data, padBits);
		}

		public virtual int getPadBits()
		{
			return padBits;
		}

		public override string ToString()
		{
			return getString();
		}

		public override int GetHashCode()
		{
			return padBits ^ Arrays.GetHashCode(this.getBytes());
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1BitString))
			{
				return false;
			}

			ASN1BitString other = (ASN1BitString)o;

			return this.padBits == other.padBits && Arrays.areEqual(this.getBytes(), other.getBytes());
		}

		protected internal static byte[] derForm(byte[] data, int padBits)
		{
			byte[] rv = Arrays.clone(data);
			// DER requires pad bits be zero
			if (padBits > 0)
			{
				rv[data.Length - 1] &= (byte)(0xff << padBits);
			}

			return rv;
		}

		internal static ASN1BitString fromInputStream(int length, InputStream stream)
		{
			if (length < 1)
			{
				throw new IllegalArgumentException("truncated BIT STRING detected");
			}

			int padBits = stream.read();
			byte[] data = new byte[length - 1];

			if (data.Length != 0)
			{
				if (Streams.readFully(stream, data) != data.Length)
				{
					throw new EOFException("EOF encountered in middle of BIT STRING");
				}

				if (padBits > 0 && padBits < 8)
				{
					if (data[data.Length - 1] != (byte)(data[data.Length - 1] & (0xff << padBits)))
					{
						return new DLBitString(data, padBits);
					}
				}
			}

			return new DERBitString(data, padBits);
		}

		public virtual ASN1Primitive getLoadedObject()
		{
			return this.toASN1Primitive();
		}

		public override ASN1Primitive toDERObject()
		{
			return new DERBitString(data, padBits);
		}

		public override ASN1Primitive toDLObject()
		{
			return new DLBitString(data, padBits);
		}

		public override abstract void encode(ASN1OutputStream @out);
	}

}