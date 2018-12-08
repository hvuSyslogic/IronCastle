using System;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.encoders
{

	/// <summary>
	/// Utility class for converting hex data to bytes and back again.
	/// </summary>
	public class Hex
	{
		private static readonly Encoder encoder = new HexEncoder();

		public static string toHexString(byte[] data)
		{
			return toHexString(data, 0, data.Length);
		}

		public static string toHexString(byte[] data, int off, int length)
		{
			byte[] encoded = encode(data, off, length);
			return Strings.fromByteArray(encoded);
		}

		/// <summary>
		/// encode the input data producing a Hex encoded byte array.
		/// </summary>
		/// <returns> a byte array containing the Hex encoded data. </returns>
		public static byte[] encode(byte[] data)
		{
			return encode(data, 0, data.Length);
		}

		/// <summary>
		/// encode the input data producing a Hex encoded byte array.
		/// </summary>
		/// <returns> a byte array containing the Hex encoded data. </returns>
		public static byte[] encode(byte[] data, int off, int length)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				encoder.encode(data, off, length, bOut);
			}
			catch (Exception e)
			{
				throw new EncoderException("exception encoding Hex string: " + e.Message, e);
			}

			return bOut.toByteArray();
		}

		/// <summary>
		/// Hex encode the byte data writing it to the given output stream.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public static int encode(byte[] data, OutputStream @out)
		{
			return encoder.encode(data, 0, data.Length, @out);
		}

		/// <summary>
		/// Hex encode the byte data writing it to the given output stream.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public static int encode(byte[] data, int off, int length, OutputStream @out)
		{
			return encoder.encode(data, off, length, @out);
		}

		/// <summary>
		/// decode the Hex encoded input data. It is assumed the input data is valid.
		/// </summary>
		/// <returns> a byte array representing the decoded data. </returns>
		public static byte[] decode(byte[] data)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				encoder.decode(data, 0, data.Length, bOut);
			}
			catch (Exception e)
			{
				throw new DecoderException("exception decoding Hex data: " + e.Message, e);
			}

			return bOut.toByteArray();
		}

		/// <summary>
		/// decode the Hex encoded String data - whitespace will be ignored.
		/// </summary>
		/// <returns> a byte array representing the decoded data. </returns>
		public static byte[] decode(string data)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				encoder.decode(data, bOut);
			}
			catch (Exception e)
			{
				throw new DecoderException("exception decoding Hex string: " + e.Message, e);
			}

			return bOut.toByteArray();
		}

		/// <summary>
		/// decode the Hex encoded String data writing it to the given output stream,
		/// whitespace characters will be ignored.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public static int decode(string data, OutputStream @out)
		{
			return encoder.decode(data, @out);
		}
	}

}