using System;

namespace org.bouncycastle.openpgp
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using MPInteger = org.bouncycastle.bcpg.MPInteger;
	using SignaturePacket = org.bouncycastle.bcpg.SignaturePacket;
	using SignatureSubpacket = org.bouncycastle.bcpg.SignatureSubpacket;
	using TrustPacket = org.bouncycastle.bcpg.TrustPacket;
	using UserAttributeSubpacket = org.bouncycastle.bcpg.UserAttributeSubpacket;
	using PGPContentVerifier = org.bouncycastle.openpgp.@operator.PGPContentVerifier;
	using PGPContentVerifierBuilder = org.bouncycastle.openpgp.@operator.PGPContentVerifierBuilder;
	using PGPContentVerifierBuilderProvider = org.bouncycastle.openpgp.@operator.PGPContentVerifierBuilderProvider;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// A PGP signature object.
	/// </summary>
	public class PGPSignature
	{
		public const int BINARY_DOCUMENT = 0x00;
		public const int CANONICAL_TEXT_DOCUMENT = 0x01;
		public const int STAND_ALONE = 0x02;

		public const int DEFAULT_CERTIFICATION = 0x10;
		public const int NO_CERTIFICATION = 0x11;
		public const int CASUAL_CERTIFICATION = 0x12;
		public const int POSITIVE_CERTIFICATION = 0x13;

		public const int SUBKEY_BINDING = 0x18;
		public const int PRIMARYKEY_BINDING = 0x19;
		public const int DIRECT_KEY = 0x1f;
		public const int KEY_REVOCATION = 0x20;
		public const int SUBKEY_REVOCATION = 0x28;
		public const int CERTIFICATION_REVOCATION = 0x30;
		public const int TIMESTAMP = 0x40;

		private SignaturePacket sigPck;
		private int signatureType;
		private TrustPacket trustPck;
		private PGPContentVerifier verifier;
		private byte lastb;
		private OutputStream sigOut;

		public PGPSignature(BCPGInputStream pIn) : this((SignaturePacket)pIn.readPacket())
		{
		}

		public PGPSignature(SignaturePacket sigPacket)
		{
			sigPck = sigPacket;
			signatureType = sigPck.getSignatureType();
			trustPck = null;
		}

		public PGPSignature(SignaturePacket sigPacket, TrustPacket trustPacket) : this(sigPacket)
		{

			this.trustPck = trustPacket;
		}

		/// <summary>
		/// Return the OpenPGP version number for this signature.
		/// </summary>
		/// <returns> signature version number. </returns>
		public virtual int getVersion()
		{
			return sigPck.getVersion();
		}

		/// <summary>
		/// Return the key algorithm associated with this signature. </summary>
		/// <returns> signature key algorithm. </returns>
		public virtual int getKeyAlgorithm()
		{
			return sigPck.getKeyAlgorithm();
		}

		/// <summary>
		/// Return the hash algorithm associated with this signature. </summary>
		/// <returns> signature hash algorithm. </returns>
		public virtual int getHashAlgorithm()
		{
			return sigPck.getHashAlgorithm();
		}

		/// <summary>
		/// Return true if this signature represents a certification.
		/// </summary>
		/// <returns> true if this signature represents a certification, false otherwise. </returns>
		public virtual bool isCertification()
		{
			return isCertification(getSignatureType());
		}

		public virtual void init(PGPContentVerifierBuilderProvider verifierBuilderProvider, PGPPublicKey pubKey)
		{
			PGPContentVerifierBuilder verifierBuilder = verifierBuilderProvider.get(sigPck.getKeyAlgorithm(), sigPck.getHashAlgorithm());

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
			this.update(bytes, 0, bytes.Length);
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

		public virtual bool verify()
		{
			try
			{
				sigOut.write(this.getSignatureTrailer());

				sigOut.close();
			}
			catch (IOException e)
			{
				throw new PGPException(e.Message, e);
			}

			return verifier.verify(this.getSignature());
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

		/// <summary>
		/// Verify the signature as certifying the passed in public key as associated
		/// with the passed in user attributes.
		/// </summary>
		/// <param name="userAttributes"> user attributes the key was stored under </param>
		/// <param name="key"> the key to be verified. </param>
		/// <returns> true if the signature matches, false otherwise. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual bool verifyCertification(PGPUserAttributeSubpacketVector userAttributes, PGPPublicKey key)
		{
			if (verifier == null)
			{
				throw new PGPException("PGPSignature not initialised - call init().");
			}

			updateWithPublicKey(key);

			//
			// hash in the userAttributes
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

			addTrailer();

			return verifier.verify(this.getSignature());
		}

		/// <summary>
		/// Verify the signature as certifying the passed in public key as associated
		/// with the passed in id.
		/// </summary>
		/// <param name="id"> id the key was stored under </param>
		/// <param name="key"> the key to be verified. </param>
		/// <returns> true if the signature matches, false otherwise. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual bool verifyCertification(string id, PGPPublicKey key)
		{
			if (verifier == null)
			{
				throw new PGPException("PGPSignature not initialised - call init().");
			}

			updateWithPublicKey(key);

			//
			// hash in the id
			//
			updateWithIdData(0xb4, Strings.toUTF8ByteArray(id));

			addTrailer();

			return verifier.verify(this.getSignature());
		}

		/// <summary>
		/// Verify the signature as certifying the passed in public key as associated
		/// with the passed in rawID.
		/// </summary>
		/// <param name="rawID"> id the key was stored under in its raw byte form. </param>
		/// <param name="key"> the key to be verified. </param>
		/// <returns> true if the signature matches, false otherwise. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual bool verifyCertification(byte[] rawID, PGPPublicKey key)
		{
			if (verifier == null)
			{
				throw new PGPException("PGPSignature not initialised - call init().");
			}

			updateWithPublicKey(key);

			//
			// hash in the rawID
			//
			updateWithIdData(0xb4, rawID);

			addTrailer();

			return verifier.verify(this.getSignature());
		}

		/// <summary>
		/// Verify a certification for the passed in key against the passed in
		/// master key.
		/// </summary>
		/// <param name="masterKey"> the key we are verifying against. </param>
		/// <param name="pubKey"> the key we are verifying. </param>
		/// <returns> true if the certification is valid, false otherwise. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual bool verifyCertification(PGPPublicKey masterKey, PGPPublicKey pubKey)
		{
			if (verifier == null)
			{
				throw new PGPException("PGPSignature not initialised - call init().");
			}

			updateWithPublicKey(masterKey);
			updateWithPublicKey(pubKey);

			addTrailer();

			return verifier.verify(this.getSignature());
		}

		private void addTrailer()
		{
			try
			{
				sigOut.write(sigPck.getSignatureTrailer());

				sigOut.close();
			}
			catch (IOException e)
			{
				throw new PGPRuntimeOperationException(e.Message, e);
			}
		}

		/// <summary>
		/// Verify a key certification, such as a revocation, for the passed in key.
		/// </summary>
		/// <param name="pubKey"> the key we are checking. </param>
		/// <returns> true if the certification is valid, false otherwise. </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual bool verifyCertification(PGPPublicKey pubKey)
		{
			if (verifier == null)
			{
				throw new PGPException("PGPSignature not initialised - call init().");
			}

			if (this.getSignatureType() != KEY_REVOCATION && this.getSignatureType() != SUBKEY_REVOCATION && this.getSignatureType() != DIRECT_KEY)
			{
				throw new PGPException("signature is not a key signature");
			}

			updateWithPublicKey(pubKey);

			addTrailer();

			return verifier.verify(this.getSignature());
		}

		public virtual int getSignatureType()
		{
			 return sigPck.getSignatureType();
		}

		/// <summary>
		/// Return the id of the key that created the signature. </summary>
		/// <returns> keyID of the signatures corresponding key. </returns>
		public virtual long getKeyID()
		{
			 return sigPck.getKeyID();
		}

		/// <summary>
		/// Return the creation time of the signature.
		/// </summary>
		/// <returns> the signature creation time. </returns>
		public virtual DateTime getCreationTime()
		{
			return new DateTime(sigPck.getCreationTime());
		}

		public virtual byte[] getSignatureTrailer()
		{
			return sigPck.getSignatureTrailer();
		}

		/// <summary>
		/// Return true if the signature has either hashed or unhashed subpackets.
		/// </summary>
		/// <returns> true if either hashed or unhashed subpackets are present, false otherwise. </returns>
		public virtual bool hasSubpackets()
		{
			return sigPck.getHashedSubPackets() != null || sigPck.getUnhashedSubPackets() != null;
		}

		public virtual PGPSignatureSubpacketVector getHashedSubPackets()
		{
			return createSubpacketVector(sigPck.getHashedSubPackets());
		}

		public virtual PGPSignatureSubpacketVector getUnhashedSubPackets()
		{
			return createSubpacketVector(sigPck.getUnhashedSubPackets());
		}

		private PGPSignatureSubpacketVector createSubpacketVector(SignatureSubpacket[] pcks)
		{
			if (pcks != null)
			{
				return new PGPSignatureSubpacketVector(pcks);
			}

			return null;
		}

		public virtual byte[] getSignature()
		{
			MPInteger[] sigValues = sigPck.getSignature();
			byte[] signature;

			if (sigValues != null)
			{
				if (sigValues.Length == 1) // an RSA signature
				{
					signature = BigIntegers.asUnsignedByteArray(sigValues[0].getValue());
				}
				else
				{
					try
					{
						ASN1EncodableVector v = new ASN1EncodableVector();
						v.add(new ASN1Integer(sigValues[0].getValue()));
						v.add(new ASN1Integer(sigValues[1].getValue()));

						signature = (new DERSequence(v)).getEncoded();
					}
					catch (IOException e)
					{
						throw new PGPException("exception encoding DSA sig.", e);
					}
				}
			}
			else
			{
				signature = sigPck.getSignatureBytes();
			}

			return signature;
		}

		public virtual byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			this.encode(bOut);

			return bOut.toByteArray();
		}

		/// <summary>
		/// Return an encoding of the signature, with trust packets stripped out if forTransfer is true.
		/// </summary>
		/// <param name="forTransfer"> if the purpose of encoding is to send key to other users. </param>
		/// <returns> a encoded byte array representing the key. </returns>
		/// <exception cref="IOException"> in case of encoding error. </exception>
		public virtual byte[] getEncoded(bool forTransfer)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			this.encode(bOut, forTransfer);

			return bOut.toByteArray();
		}

		public virtual void encode(OutputStream outStream)
		{
			encode(outStream, false);
		}

		/// <summary>
		/// Encode the signature to outStream, with trust packets stripped out if forTransfer is true.
		/// </summary>
		/// <param name="outStream"> stream to write the key encoding to. </param>
		/// <param name="forTransfer"> if the purpose of encoding is to send key to other users. </param>
		/// <exception cref="IOException"> in case of encoding error. </exception>
		public virtual void encode(OutputStream outStream, bool forTransfer)
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

			@out.writePacket(sigPck);
			if (!forTransfer && trustPck != null)
			{
				@out.writePacket(trustPck);
			}
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

		/// <summary>
		/// Return true if the passed in signature type represents a certification, false if the signature type is not.
		/// </summary>
		/// <param name="signatureType"> </param>
		/// <returns> true if signatureType is a certification, false otherwise. </returns>
		public static bool isCertification(int signatureType)
		{
			return PGPSignature.DEFAULT_CERTIFICATION == signatureType || PGPSignature.NO_CERTIFICATION == signatureType || PGPSignature.CASUAL_CERTIFICATION == signatureType || PGPSignature.POSITIVE_CERTIFICATION == signatureType;
		}
	}

}