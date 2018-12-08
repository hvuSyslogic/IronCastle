using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp
{

	using MPInteger = org.bouncycastle.bcpg.MPInteger;
	using OnePassSignaturePacket = org.bouncycastle.bcpg.OnePassSignaturePacket;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using SignaturePacket = org.bouncycastle.bcpg.SignaturePacket;
	using SignatureSubpacket = org.bouncycastle.bcpg.SignatureSubpacket;
	using SignatureSubpacketTags = org.bouncycastle.bcpg.SignatureSubpacketTags;
	using UserAttributeSubpacket = org.bouncycastle.bcpg.UserAttributeSubpacket;
	using IssuerKeyID = org.bouncycastle.bcpg.sig.IssuerKeyID;
	using SignatureCreationTime = org.bouncycastle.bcpg.sig.SignatureCreationTime;
	using PGPContentSigner = org.bouncycastle.openpgp.@operator.PGPContentSigner;
	using PGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.PGPContentSignerBuilder;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Generator for PGP Signatures.
	/// </summary>
	public class PGPSignatureGenerator
	{
		private SignatureSubpacket[] unhashed = new SignatureSubpacket[0];
		private SignatureSubpacket[] hashed = new SignatureSubpacket[0];
		private OutputStream sigOut;
		private PGPContentSignerBuilder contentSignerBuilder;
		private PGPContentSigner contentSigner;
		private int sigType;
		private byte lastb;
		private int providedKeyAlgorithm = -1;

		/// <summary>
		/// Create a signature generator built on the passed in contentSignerBuilder.
		/// </summary>
		/// <param name="contentSignerBuilder">  builder to produce PGPContentSigner objects for generating signatures. </param>
		public PGPSignatureGenerator(PGPContentSignerBuilder contentSignerBuilder)
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

		public virtual void setHashedSubpackets(PGPSignatureSubpacketVector hashedPcks)
		{
			if (hashedPcks == null)
			{
				hashed = new SignatureSubpacket[0];
				return;
			}

			hashed = hashedPcks.toSubpacketArray();
		}

		public virtual void setUnhashedSubpackets(PGPSignatureSubpacketVector unhashedPcks)
		{
			if (unhashedPcks == null)
			{
				unhashed = new SignatureSubpacket[0];
				return;
			}

			unhashed = unhashedPcks.toSubpacketArray();
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
		/// Return a signature object containing the current signature state.
		/// </summary>
		/// <returns> PGPSignature </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPSignature generate()
		{
			MPInteger[] sigValues;
			int version = 4;
			ByteArrayOutputStream sOut = new ByteArrayOutputStream();
			SignatureSubpacket[] hPkts, unhPkts;

			if (!packetPresent(hashed, SignatureSubpacketTags_Fields.CREATION_TIME))
			{
				hPkts = insertSubpacket(hashed, new SignatureCreationTime(false, DateTime.Now));
			}
			else
			{
				hPkts = hashed;
			}

			if (!packetPresent(hashed, SignatureSubpacketTags_Fields.ISSUER_KEY_ID) && !packetPresent(unhashed, SignatureSubpacketTags_Fields.ISSUER_KEY_ID))
			{
				unhPkts = insertSubpacket(unhashed, new IssuerKeyID(false, contentSigner.getKeyID()));
			}
			else
			{
				unhPkts = unhashed;
			}

			try
			{
				sOut.write((byte)version);
				sOut.write((byte)sigType);
				sOut.write((byte)contentSigner.getKeyAlgorithm());
				sOut.write((byte)contentSigner.getHashAlgorithm());

				ByteArrayOutputStream hOut = new ByteArrayOutputStream();

				for (int i = 0; i != hPkts.Length; i++)
				{
					hPkts[i].encode(hOut);
				}

				byte[] data = hOut.toByteArray();

				sOut.write((byte)(data.Length >> 8));
				sOut.write((byte)data.Length);
				sOut.write(data);
			}
			catch (IOException e)
			{
				throw new PGPException("exception encoding hashed data.", e);
			}

			byte[] hData = sOut.toByteArray();

			sOut.write((byte)version);
			sOut.write(unchecked((byte)0xff));
			sOut.write((byte)(hData.Length >> 24));
			sOut.write((byte)(hData.Length >> 16));
			sOut.write((byte)(hData.Length >> 8));
			sOut.write((byte)(hData.Length));

			byte[] trailer = sOut.toByteArray();

			blockUpdate(trailer, 0, trailer.Length);

			if (contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags_Fields.RSA_SIGN || contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags_Fields.RSA_GENERAL) // an RSA signature
			{
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

			return new PGPSignature(new SignaturePacket(sigType, contentSigner.getKeyID(), contentSigner.getKeyAlgorithm(), contentSigner.getHashAlgorithm(), hPkts, unhPkts, fingerPrint, sigValues));
		}

		/// <summary>
		/// Generate a certification for the passed in id and key.
		/// </summary>
		/// <param name="id"> the id we are certifying against the public key. </param>
		/// <param name="pubKey"> the key we are certifying against the id. </param>
		/// <returns> the certification. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPSignature generateCertification(string id, PGPPublicKey pubKey)
		{
			updateWithPublicKey(pubKey);

			//
			// hash in the id
			//
			updateWithIdData(0xb4, Strings.toUTF8ByteArray(id));

			return this.generate();
		}

		/// <summary>
		/// Generate a certification for the passed in userAttributes </summary>
		/// <param name="userAttributes"> the id we are certifying against the public key. </param>
		/// <param name="pubKey"> the key we are certifying against the id. </param>
		/// <returns> the certification. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPSignature generateCertification(PGPUserAttributeSubpacketVector userAttributes, PGPPublicKey pubKey)
		{
			updateWithPublicKey(pubKey);

			//
			// hash in the attributes
			//
			try
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				UserAttributeSubpacket[] packets = userAttributes.toSubpacketArray();
				for (int i = 0; i != packets.Length; i++)
				{
					packets[i].encode(bOut);
				}
				updateWithIdData(0xd1, bOut.toByteArray());
			}
			catch (IOException e)
			{
				throw new PGPException("cannot encode subpacket array", e);
			}

			return this.generate();
		}

		/// <summary>
		/// Generate a certification for the passed in key against the passed in
		/// master key.
		/// </summary>
		/// <param name="masterKey"> the key we are certifying against. </param>
		/// <param name="pubKey"> the key we are certifying. </param>
		/// <returns> the certification. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPSignature generateCertification(PGPPublicKey masterKey, PGPPublicKey pubKey)
		{
			updateWithPublicKey(masterKey);
			updateWithPublicKey(pubKey);

			return this.generate();
		}

		/// <summary>
		/// Generate a certification, such as a revocation, for the passed in key.
		/// </summary>
		/// <param name="pubKey"> the key we are certifying. </param>
		/// <returns> the certification. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPSignature generateCertification(PGPPublicKey pubKey)
		{
			if ((sigType == PGPSignature.SUBKEY_REVOCATION || sigType == PGPSignature.SUBKEY_BINDING) && !pubKey.isMasterKey())
			{
				throw new IllegalArgumentException("certifications involving subkey requires public key of revoking key as well.");
			}

			updateWithPublicKey(pubKey);

			return this.generate();
		}

		private byte[] getEncodedPublicKey(PGPPublicKey pubKey)
		{
			byte[] keyBytes;

			try
			{
				keyBytes = pubKey.publicPk.getEncodedContents();
			}
			catch (IOException e)
			{
				throw new PGPException("exception preparing key.", e);
			}

			return keyBytes;
		}

		private bool packetPresent(SignatureSubpacket[] packets, int type)
		{
			for (int i = 0; i != packets.Length; i++)
			{
				if (packets[i].getType() == type)
				{
					return true;
				}
			}

			return false;
		}

		private SignatureSubpacket[] insertSubpacket(SignatureSubpacket[] packets, SignatureSubpacket subpacket)
		{
			SignatureSubpacket[] tmp = new SignatureSubpacket[packets.Length + 1];

			tmp[0] = subpacket;
			JavaSystem.arraycopy(packets, 0, tmp, 1, packets.Length);

			return tmp;
		}

		private void updateWithIdData(int header, byte[] idBytes)
		{
			this.update((byte)header);
			this.update((byte)(idBytes.Length >> 24));
			this.update((byte)(idBytes.Length >> 16));
			this.update((byte)(idBytes.Length >> 8));
			this.update((byte)(idBytes.Length));
			this.update(idBytes);
		}

		private void updateWithPublicKey(PGPPublicKey key)
		{
			byte[] keyBytes = getEncodedPublicKey(key);

			this.update(unchecked((byte)0x99));
			this.update((byte)(keyBytes.Length >> 8));
			this.update((byte)(keyBytes.Length));
			this.update(keyBytes);
		}
	}

}