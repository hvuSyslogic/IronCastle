using System;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.encoders
{

	/// <summary>
	/// Utility class for converting Base64 data to bytes and back again.
	/// </summary>
	public class Base64
	{
		private static readonly Encoder encoder = new Base64Encoder();

		public static string toBase64String(byte[] data)
		{
			return toBase64String(data, 0, data.Length);
		}

		public static string toBase64String(byte[] data, int off, int length)
		{
			byte[] encoded = encode(data, off, length);
			return Strings.fromByteArray(encoded);
		}

		/// <summary>
		/// encode the input data producing a base 64 encoded byte array.
		/// </summary>
		/// <returns> a byte array containing the base 64 encoded data. </returns>
		public static byte[] encode(byte[] data)
		{
			return encode(data, 0, data.Length);
		}

		/// <summary>
		/// encode the input data producing a base 64 encoded byte array.
		/// </summary>
		/// <returns> a byte array containing the base 64 encoded data. </returns>
		public static byte[] encode(byte[] data, int off, int length)
		{
			int len = (length + 2) / 3 * 4;
			ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

			try
			{
				encoder.encode(data, off, length, bOut);
			}
			catch (Exception e)
			{
				throw new EncoderException("exception encoding base64 string: " + e.Message, e);
			}

			return bOut.toByteArray();
		}

		/// <summary>
		/// Encode the byte data to base 64 writing it to the given output stream.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public static int encode(byte[] data, OutputStream @out)
		{
			return encoder.encode(data, 0, data.Length, @out);
		}

		/// <summary>
		/// Encode the byte data to base 64 writing it to the given output stream.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public static int encode(byte[] data, int off, int length, OutputStream @out)
		{
			return encoder.encode(data, off, length, @out);
		}

		/// <summary>
		/// decode the base 64 encoded input data. It is assumed the input data is valid.
		/// </summary>
		/// <returns> a byte array representing the decoded data. </returns>
		public static byte[] decode(byte[] data)
		{
			int len = data.Length / 4 * 3;
			ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

			try
			{
				encoder.decode(data, 0, data.Length, bOut);
			}
			catch (Exception e)
			{
				throw new DecoderException("unable to decode base64 data: " + e.Message, e);
			}

			return bOut.toByteArray();
		}

		/// <summary>
		/// decode the base 64 encoded String data - whitespace will be ignored.
		/// </summary>
		/// <returns> a byte array representing the decoded data. </returns>
		public static byte[] decode(string data)
		{
			int len = data.Length / 4 * 3;
			ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

			try
			{
				encoder.decode(data, bOut);
			}
			catch (Exception e)
			{
				throw new DecoderException("unable to decode base64 string: " + e.Message, e);
			}

			return bOut.toByteArray();
		}

		/// <summary>
		/// decode the base 64 encoded String data writing it to the given output stream,
		/// whitespace characters will be ignored.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public static int decode(string data, OutputStream @out)
		{
			return encoder.decode(data, @out);
		}

		/// <summary>
		/// Decode to an output stream;
		/// </summary>
		/// <param name="base64Data">       The source data. </param>
		/// <param name="start">            Start position. </param>
		/// <param name="length">           the length. </param>
		/// <param name="out"> The output stream to write to. </param>
		public static int decode(byte[] base64Data, int start, int length, OutputStream @out)
		{
			try
			{
			   return encoder.decode(base64Data, start, length, @out);
			}
			catch (Exception e)
			{
				throw new DecoderException("unable to decode base64 data: " + e.Message, e);
			}

		}
	}

}