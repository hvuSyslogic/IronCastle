using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.encoders
{

	/// <summary>
	/// A streaming Hex encoder.
	/// </summary>
	public class HexEncoder : Encoder
	{
		protected internal readonly byte[] encodingTable = new byte[] {(byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7', (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'};

		/*
		 * set up the decoding table.
		 */
		protected internal readonly byte[] decodingTable = new byte[128];

		public virtual void initialiseDecodingTable()
		{
			for (int i = 0; i < decodingTable.Length; i++)
			{
				decodingTable[i] = unchecked(0xff);
			}

			for (int i = 0; i < encodingTable.Length; i++)
			{
				decodingTable[encodingTable[i]] = (byte)i;
			}

			decodingTable['A'] = decodingTable['a'];
			decodingTable['B'] = decodingTable['b'];
			decodingTable['C'] = decodingTable['c'];
			decodingTable['D'] = decodingTable['d'];
			decodingTable['E'] = decodingTable['e'];
			decodingTable['F'] = decodingTable['f'];
		}

		public HexEncoder()
		{
			initialiseDecodingTable();
		}

		/// <summary>
		/// encode the input data producing a Hex output stream.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public virtual int encode(byte[] data, int off, int length, OutputStream @out)
		{
			for (int i = off; i < (off + length); i++)
			{
				int v = data[i] & 0xff;

				@out.write(encodingTable[((int)((uint)v >> 4))]);
				@out.write(encodingTable[v & 0xf]);
			}

			return length * 2;
		}

		private static bool ignore(char c)
		{
			return c == '\n' || c == '\r' || c == '\t' || c == ' ';
		}

		/// <summary>
		/// decode the Hex encoded byte data writing it to the given output stream,
		/// whitespace characters will be ignored.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public virtual int decode(byte[] data, int off, int length, OutputStream @out)
		{
			byte b1, b2;
			int outLen = 0;

			int end = off + length;

			while (end > off)
			{
				if (!ignore((char)data[end - 1]))
				{
					break;
				}

				end--;
			}

			int i = off;
			while (i < end)
			{
				while (i < end && ignore((char)data[i]))
				{
					i++;
				}

				b1 = decodingTable[data[i++]];

				while (i < end && ignore((char)data[i]))
				{
					i++;
				}

				b2 = decodingTable[data[i++]];

				if ((b1 | b2) < 0)
				{
					throw new IOException("invalid characters encountered in Hex data");
				}

				@out.write((b1 << 4) | b2);

				outLen++;
			}

			return outLen;
		}

		/// <summary>
		/// decode the Hex encoded String data writing it to the given output stream,
		/// whitespace characters will be ignored.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public virtual int decode(string data, OutputStream @out)
		{
			byte b1, b2;
			int length = 0;

			int end = data.Length;

			while (end > 0)
			{
				if (!ignore(data[end - 1]))
				{
					break;
				}

				end--;
			}

			int i = 0;
			while (i < end)
			{
				while (i < end && ignore(data[i]))
				{
					i++;
				}

				b1 = decodingTable[data[i++]];

				while (i < end && ignore(data[i]))
				{
					i++;
				}

				b2 = decodingTable[data[i++]];

				if ((b1 | b2) < 0)
				{
					throw new IOException("invalid characters encountered in Hex string");
				}

				@out.write((b1 << 4) | b2);

				length++;
			}

			return length;
		}
	}

}