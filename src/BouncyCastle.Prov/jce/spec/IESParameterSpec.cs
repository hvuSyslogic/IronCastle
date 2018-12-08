namespace org.bouncycastle.jce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Parameter spec for an integrated encryptor, as in IEEE P1363a
	/// </summary>
	public class IESParameterSpec : AlgorithmParameterSpec
	{
		private byte[] derivation;
		private byte[] encoding;
		private int macKeySize;
		private int cipherKeySize;
		private byte[] nonce;
		private bool usePointCompression;


		/// <summary>
		/// Set the IES engine parameters.
		/// </summary>
		/// <param name="derivation"> the optional derivation vector for the KDF. </param>
		/// <param name="encoding">   the optional encoding vector for the KDF. </param>
		/// <param name="macKeySize"> the key size (in bits) for the MAC. </param>
		public IESParameterSpec(byte[] derivation, byte[] encoding, int macKeySize) : this(derivation, encoding, macKeySize, -1, null, false)
		{
		}

		/// <summary>
		/// Set the IES engine parameters.
		/// </summary>
		/// <param name="derivation">    the optional derivation vector for the KDF. </param>
		/// <param name="encoding">      the optional encoding vector for the KDF. </param>
		/// <param name="macKeySize">    the key size (in bits) for the MAC. </param>
		/// <param name="cipherKeySize"> the key size (in bits) for the block cipher. </param>
		/// <param name="nonce">         an IV to use initialising the block cipher. </param>
		public IESParameterSpec(byte[] derivation, byte[] encoding, int macKeySize, int cipherKeySize, byte[] nonce) : this(derivation, encoding, macKeySize, cipherKeySize, nonce, false)
		{
		}

		/// <summary>
		/// Set the IES engine parameters.
		/// </summary>
		/// <param name="derivation">    the optional derivation vector for the KDF. </param>
		/// <param name="encoding">      the optional encoding vector for the KDF. </param>
		/// <param name="macKeySize">    the key size (in bits) for the MAC. </param>
		/// <param name="cipherKeySize"> the key size (in bits) for the block cipher. </param>
		/// <param name="nonce">         an IV to use initialising the block cipher. </param>
		/// <param name="usePointCompression"> whether to use EC point compression or not (false by default) </param>
		public IESParameterSpec(byte[] derivation, byte[] encoding, int macKeySize, int cipherKeySize, byte[] nonce, bool usePointCompression)
		{
			if (derivation != null)
			{
				this.derivation = new byte[derivation.Length];
				JavaSystem.arraycopy(derivation, 0, this.derivation, 0, derivation.Length);
			}
			else
			{
				this.derivation = null;
			}

			if (encoding != null)
			{
				this.encoding = new byte[encoding.Length];
				JavaSystem.arraycopy(encoding, 0, this.encoding, 0, encoding.Length);
			}
			else
			{
				this.encoding = null;
			}

			this.macKeySize = macKeySize;
			this.cipherKeySize = cipherKeySize;
			this.nonce = Arrays.clone(nonce);
			this.usePointCompression = usePointCompression;
		}

		/// <summary>
		/// return the derivation vector.
		/// </summary>
		public virtual byte[] getDerivationV()
		{
			return Arrays.clone(derivation);
		}

		/// <summary>
		/// return the encoding vector.
		/// </summary>
		public virtual byte[] getEncodingV()
		{
			return Arrays.clone(encoding);
		}

		/// <summary>
		/// return the key size in bits for the MAC used with the message
		/// </summary>
		public virtual int getMacKeySize()
		{
			return macKeySize;
		}

		/// <summary>
		/// return the key size in bits for the block cipher used with the message
		/// </summary>
		public virtual int getCipherKeySize()
		{
			return cipherKeySize;
		}

		/// <summary>
		/// Return the nonce (IV) value to be associated with message.
		/// </summary>
		/// <returns> block cipher IV for message. </returns>
		public virtual byte[] getNonce()
		{
			return Arrays.clone(nonce);
		}

		/// <summary>
		/// Set the 'point compression' flag.
		/// </summary>
		public virtual void setPointCompression(bool usePointCompression)
		{
			this.usePointCompression = usePointCompression;
		}

		/// <summary>
		/// Return the 'point compression' flag.
		/// </summary>
		/// <returns> the point compression flag </returns>
		public virtual bool getPointCompression()
		{
			return usePointCompression;
		}
	}
}