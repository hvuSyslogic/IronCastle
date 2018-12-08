using System;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.encoders
{

	/// <summary>
	/// Convert binary data to and from UrlBase64 encoding.  This is identical to
	/// Base64 encoding, except that the padding character is "." and the other 
	/// non-alphanumeric characters are "-" and "_" instead of "+" and "/".
	/// <para>
	/// The purpose of UrlBase64 encoding is to provide a compact encoding of binary
	/// data that is safe for use as an URL parameter. Base64 encoding does not
	/// produce encoded values that are safe for use in URLs, since "/" can be 
	/// interpreted as a path delimiter; "+" is the encoded form of a space; and
	/// "=" is used to separate a name from the corresponding value in an URL 
	/// parameter.
	/// </para>
	/// </summary>
	public class UrlBase64
	{
		private static readonly Encoder encoder = new UrlBase64Encoder();

		/// <summary>
		/// Encode the input data producing a URL safe base 64 encoded byte array.
		/// </summary>
		/// <returns> a byte array containing the URL safe base 64 encoded data. </returns>
		public static byte[] encode(byte[] data)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				encoder.encode(data, 0, data.Length, bOut);
			}
			catch (Exception e)
			{
				throw new EncoderException("exception encoding URL safe base64 data: " + e.Message, e);
			}

			return bOut.toByteArray();
		}

		/// <summary>
		/// Encode the byte data writing it to the given output stream.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public static int encode(byte[] data, OutputStream @out)
		{
			return encoder.encode(data, 0, data.Length, @out);
		}

		/// <summary>
		/// Decode the URL safe base 64 encoded input data - white space will be ignored.
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
				throw new DecoderException("exception decoding URL safe base64 string: " + e.Message, e);
			}

			return bOut.toByteArray();
		}

		/// <summary>
		/// decode the URL safe base 64 encoded byte data writing it to the given output stream,
		/// whitespace characters will be ignored.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public static int decode(byte[] data, OutputStream @out)
		{
			return encoder.decode(data, 0, data.Length, @out);
		}

		/// <summary>
		/// decode the URL safe base 64 encoded String data - whitespace will be ignored.
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
				throw new DecoderException("exception decoding URL safe base64 string: " + e.Message, e);
			}

			return bOut.toByteArray();
		}

		/// <summary>
		/// Decode the URL safe base 64 encoded String data writing it to the given output stream,
		/// whitespace characters will be ignored.
		/// </summary>
		/// <returns> the number of bytes produced. </returns>
		public static int decode(string data, OutputStream @out)
		{
			return encoder.decode(data, @out);
		}
	}

}