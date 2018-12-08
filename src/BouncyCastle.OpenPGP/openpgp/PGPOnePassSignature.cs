namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using OnePassSignaturePacket = org.bouncycastle.bcpg.OnePassSignaturePacket;
	using PGPContentVerifier = org.bouncycastle.openpgp.@operator.PGPContentVerifier;
	using PGPContentVerifierBuilder = org.bouncycastle.openpgp.@operator.PGPContentVerifierBuilder;
	using PGPContentVerifierBuilderProvider = org.bouncycastle.openpgp.@operator.PGPContentVerifierBuilderProvider;

	/// <summary>
	/// A one pass signature object.
	/// </summary>
	public class PGPOnePassSignature
	{
		private OnePassSignaturePacket sigPack;
		private int signatureType;

		private PGPContentVerifier verifier;
		private byte lastb;
		private OutputStream sigOut;

		public PGPOnePassSignature(BCPGInputStream pIn) : this((OnePassSignaturePacket)pIn.readPacket())
		{
		}

		public PGPOnePassSignature(OnePassSignaturePacket sigPack)
		{
			this.sigPack = sigPack;
			this.signatureType = sigPack.getSignatureType();
		}

		/// <summary>
		/// Initialise the signature object for verification.
		/// </summary>
		/// <param name="verifierBuilderProvider">   provider for a content verifier builder for the signature type of interest. </param>
		/// <param name="pubKey">  the public key to use for verification </param>
		/// <exception cref="PGPException"> if there's an issue with creating the verifier. </exception>
		public virtual void init(PGPContentVerifierBuilderProvider verifierBuilderProvider, PGPPublicKey pubKey)
		{
			PGPContentVerifierBuilder verifierBuilder = verifierBuilderProvider.get(sigPack.getKeyAlgorithm(), sigPack.getHashAlgorithm());

			verifier = verifierBuilder.build(pubKey);

			lastb = 0;
			sigOut = verifier.getOutputStream();
		}

		public virtual void update(byte b)
		{
			if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
			{
				if (b == (byte)'\r')
				{
					byteUpdate((byte)'\r');
					byteUpdate((byte)'\n');
				}
				else if (b == (byte)'\n')
				{
					if (lastb != (byte)'\r')
					{
						byteUpdate((byte)'\r');
						byteUpdate((byte)'\n');
					}
				}
				else
				{
					byteUpdate(b);
				}

				lastb = b;
			}
			else
			{
				byteUpdate(b);
			}
		}

		public virtual void update(byte[] bytes)
		{
			if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
			{
				for (int i = 0; i != bytes.Length; i++)
				{
					this.update(bytes[i]);
				}
			}
			else
			{
				blockUpdate(bytes, 0, bytes.Length);
			}
		}

		public virtual void update(byte[] bytes, int off, int length)
		{
			if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
			{
				int finish = off + length;

				for (int i = off; i != finish; i++)
				{
					this.update(bytes[i]);
				}
			}
			else
			{
				blockUpdate(bytes, off, length);
			}
		}

		private void byteUpdate(byte b)
		{
			try
			{
				sigOut.write(b);
			}
			catch (IOException e)
			{
				throw new PGPRuntimeOperationException(e.Message, e);
			}
		}

		private void blockUpdate(byte[] block, int off, int len)
		{
			try
			{
				sigOut.write(block, off, len);
			}
			catch (IOException e)
			{
				throw new PGPRuntimeOperationException(e.Message, e);
			}
		}

		/// <summary>
		/// Verify the calculated signature against the passed in PGPSignature.
		/// </summary>
		/// <param name="pgpSig"> </param>
		/// <returns> boolean </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual bool verify(PGPSignature pgpSig)
		{
			try
			{
				sigOut.write(pgpSig.getSignatureTrailer());

				sigOut.close();
			}
			catch (IOException e)
			{
				throw new PGPException("unable to add trailer: " + e.Message, e);
			}

			return verifier.verify(pgpSig.getSignature());
		}

		public virtual long getKeyID()
		{
			return sigPack.getKeyID();
		}

		public virtual int getSignatureType()
		{
			return sigPack.getSignatureType();
		}

		public virtual int getHashAlgorithm()
		{
			return sigPack.getHashAlgorithm();
		}

		public virtual int getKeyAlgorithm()
		{
			return sigPack.getKeyAlgorithm();
		}

		public virtual byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			this.encode(bOut);

			return bOut.toByteArray();
		}

		public virtual void encode(OutputStream outStream)
		{
			BCPGOutputStream @out;

			if (outStream is BCPGOutputStream)
			{
				@out = (BCPGOutputStream)outStream;
			}
			else
			{
				@out = new BCPGOutputStream(outStream);
			}

			@out.writePacket(sigPack);
		}
	}

}