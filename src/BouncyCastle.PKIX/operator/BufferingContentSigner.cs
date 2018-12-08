namespace org.bouncycastle.@operator
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BufferingOutputStream = org.bouncycastle.util.io.BufferingOutputStream;

	/// <summary>
	/// A class that explicitly buffers the data to be signed, sending it in one
	/// block when ready for signing.
	/// </summary>
	public class BufferingContentSigner : ContentSigner
	{
		private readonly ContentSigner contentSigner;
		private readonly OutputStream output;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="contentSigner"> the content signer to be wrapped. </param>
		public BufferingContentSigner(ContentSigner contentSigner)
		{
			this.contentSigner = contentSigner;
			this.output = new BufferingOutputStream(contentSigner.getOutputStream());
		}

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="contentSigner"> the content signer to be wrapped. </param>
		/// <param name="bufferSize"> the size of the internal buffer to use. </param>
		public BufferingContentSigner(ContentSigner contentSigner, int bufferSize)
		{
			this.contentSigner = contentSigner;
			this.output = new BufferingOutputStream(contentSigner.getOutputStream(), bufferSize);
		}

		/// <summary>
		/// Return the algorithm identifier supported by this signer.
		/// </summary>
		/// <returns> algorithm identifier for the signature generated. </returns>
		public virtual AlgorithmIdentifier getAlgorithmIdentifier()
		{
			return contentSigner.getAlgorithmIdentifier();
		}

		/// <summary>
		/// Return the buffering stream.
		/// </summary>
		/// <returns> the output stream used to accumulate the data. </returns>
		public virtual OutputStream getOutputStream()
		{
			return output;
		}

		/// <summary>
		/// Generate signature from internally buffered data.
		/// </summary>
		/// <returns> the signature calculated from the bytes written to the buffering stream. </returns>
		public virtual byte[] getSignature()
		{
			return contentSigner.getSignature();
		}
	}

}