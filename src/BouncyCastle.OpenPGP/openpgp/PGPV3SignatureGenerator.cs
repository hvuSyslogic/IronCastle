using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp
{

	using MPInteger = org.bouncycastle.bcpg.MPInteger;
	using OnePassSignaturePacket = org.bouncycastle.bcpg.OnePassSignaturePacket;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using SignaturePacket = org.bouncycastle.bcpg.SignaturePacket;
	using PGPContentSigner = org.bouncycastle.openpgp.@operator.PGPContentSigner;
	using PGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.PGPContentSignerBuilder;

	/// <summary>
	/// Generator for old style PGP V3 Signatures.
	/// </summary>
	public class PGPV3SignatureGenerator
	{
		private byte lastb;
		private OutputStream sigOut;
		private PGPContentSignerBuilder contentSignerBuilder;
		private PGPContentSigner contentSigner;
		private int sigType;
		private int providedKeyAlgorithm = -1;

		/// <summary>
		/// Create a signature generator built on the passed in contentSignerBuilder.
		/// </summary>
		/// <param name="contentSignerBuilder">  builder to produce PGPContentSigner objects for generating signatures. </param>
		public PGPV3SignatureGenerator(PGPContentSignerBuilder contentSignerBuilder)
		{
			this.contentSignerBuilder = contentSignerBuilder;
		}

		/// <summary>
		/// Initialise the generator for signing.
		/// </summary>
		/// <param name="signatureType"> </param>
		/// <param name="key"> </param>
		/// <exception cref="PGPException"> </exception>
		public virtual void init(int signatureType, PGPPrivateKey key)
		{
			contentSigner = contentSignerBuilder.build(signatureType, key);
			sigOut = contentSigner.getOutputStream();
			sigType = contentSigner.getType();
			lastb = 0;

			if (providedKeyAlgorithm >= 0 && providedKeyAlgorithm != contentSigner.getKeyAlgorithm())
			{
				throw new PGPException("key algorithm mismatch");
			}
		}

		public virtual void update(byte b)
		{
			if (sigType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
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

		public virtual void update(byte[] b)
		{
			this.update(b, 0, b.Length);
		}

		public virtual void update(byte[] b, int off, int len)
		{
			if (sigType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
			{
				int finish = off + len;

				for (int i = off; i != finish; i++)
				{
					this.update(b[i]);
				}
			}
			else
			{
				blockUpdate(b, off, len);
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
				throw new PGPRuntimeOperationException("unable to update signature: " + e.Message, e);
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
				throw new PGPRuntimeOperationException("unable to update signature: " + e.Message, e);
			}
		}

		/// <summary>
		/// Return the one pass header associated with the current signature.
		/// </summary>
		/// <param name="isNested"> </param>
		/// <returns> PGPOnePassSignature </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPOnePassSignature generateOnePassVersion(bool isNested)
		{
			return new PGPOnePassSignature(new OnePassSignaturePacket(sigType, contentSigner.getHashAlgorithm(), contentSigner.getKeyAlgorithm(), contentSigner.getKeyID(), isNested));
		}

		/// <summary>
		/// Return a V3 signature object containing the current signature state.
		/// </summary>
		/// <returns> PGPSignature </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPSignature generate()
		{
			long creationTime = (DateTime.Now).Ticks / 1000;

			ByteArrayOutputStream sOut = new ByteArrayOutputStream();

			sOut.write(sigType);
			sOut.write((byte)(creationTime >> 24));
			sOut.write((byte)(creationTime >> 16));
			sOut.write((byte)(creationTime >> 8));
			sOut.write((byte)creationTime);

			byte[] hData = sOut.toByteArray();

			blockUpdate(hData, 0, hData.Length);

			MPInteger[] sigValues;
			if (contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags_Fields.RSA_SIGN || contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags_Fields.RSA_GENERAL)
			{
				// an RSA signature
				sigValues = new MPInteger[1];
				sigValues[0] = new MPInteger(new BigInteger(1, contentSigner.getSignature()));
			}
			else
			{
				sigValues = PGPUtil.dsaSigToMpi(contentSigner.getSignature());
			}

			byte[] digest = contentSigner.getDigest();
			byte[] fingerPrint = new byte[2];

			fingerPrint[0] = digest[0];
			fingerPrint[1] = digest[1];

			return new PGPSignature(new SignaturePacket(3, contentSigner.getType(), contentSigner.getKeyID(), contentSigner.getKeyAlgorithm(), contentSigner.getHashAlgorithm(), creationTime * 1000, fingerPrint, sigValues));
		}
	}

}