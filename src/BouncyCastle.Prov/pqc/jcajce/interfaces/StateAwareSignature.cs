namespace org.bouncycastle.pqc.jcajce.interfaces
{

	/// <summary>
	/// This interface is implemented by Signature classes returned by the PQC provider where the signature
	/// algorithm is one where the private key is updated for each signature generated. Examples of these
	/// are algorithms such as GMSS, XMSS, and XMSS^MT.
	/// </summary>
	public interface StateAwareSignature
	{
		void initVerify(PublicKey publicKey);

		void initVerify(Certificate certificate);

		void initSign(PrivateKey privateKey);

		void initSign(PrivateKey privateKey, SecureRandom random);

		byte[] sign();

		int sign(byte[] outbuf, int offset, int len);

		bool verify(byte[] signature);

		bool verify(byte[] signature, int offset, int length);

		void update(byte b);

		void update(byte[] data);

		void update(byte[] data, int off, int len);

		void update(ByteBuffer data);

		string getAlgorithm();

		/// <summary>
		/// Return true if this Signature object can be used for signing. False otherwise.
		/// </summary>
		/// <returns> true if we are capable of making signatures. </returns>
		bool isSigningCapable();

		/// <summary>
		/// Return the current version of the private key with the updated state.
		/// <para>
		/// <b>Note:</b> calling this method will effectively disable the Signature object from being used for further
		///  signature generation without another call to initSign().
		/// </para> </summary>
		/// <returns> an updated private key object, which can be used for later signature generation. </returns>
	   PrivateKey getUpdatedPrivateKey();
	}

}