using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Basic class for streaming generators.
	/// </summary>
	public abstract class ASN1Generator
	{
		protected internal OutputStream _out;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="out"> the end output stream that object encodings are written to. </param>
		public ASN1Generator(OutputStream @out)
		{
			_out = @out;
		}

		/// <summary>
		/// Return the actual stream object encodings are written to.
		/// </summary>
		/// <returns> the stream that is directly encoded to. </returns>
		public abstract OutputStream getRawOutputStream();
	}

}