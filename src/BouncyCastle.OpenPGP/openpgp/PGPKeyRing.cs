using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using Packet = org.bouncycastle.bcpg.Packet;
	using PacketTags = org.bouncycastle.bcpg.PacketTags;
	using SignaturePacket = org.bouncycastle.bcpg.SignaturePacket;
	using TrustPacket = org.bouncycastle.bcpg.TrustPacket;
	using UserAttributePacket = org.bouncycastle.bcpg.UserAttributePacket;
	using UserIDPacket = org.bouncycastle.bcpg.UserIDPacket;

	/// <summary>
	/// Parent class for PGP public and secret key rings.
	/// </summary>
	public abstract class PGPKeyRing
	{
		public PGPKeyRing()
		{
		}

		internal static BCPGInputStream wrap(InputStream @in)
		{
			if (@in is BCPGInputStream)
			{
				return (BCPGInputStream)@in;
			}

			return new BCPGInputStream(@in);
		}

		internal static TrustPacket readOptionalTrustPacket(BCPGInputStream pIn)
		{
			return (pIn.nextPacketTag() == PacketTags_Fields.TRUST) ? (TrustPacket) pIn.readPacket() : null;
		}

		internal static List readSignaturesAndTrust(BCPGInputStream pIn)
		{
			try
			{
				List sigList = new ArrayList();

				while (pIn.nextPacketTag() == PacketTags_Fields.SIGNATURE)
				{
					SignaturePacket signaturePacket = (SignaturePacket)pIn.readPacket();
					TrustPacket trustPacket = readOptionalTrustPacket(pIn);

					sigList.add(new PGPSignature(signaturePacket, trustPacket));
				}

				return sigList;
			}
			catch (PGPException e)
			{
				throw new IOException("can't create signature object: " + e.Message + ", cause: " + e.getUnderlyingException().ToString());
			}
		}

		internal static void readUserIDs(BCPGInputStream pIn, List ids, List idTrusts, List idSigs)
		{
			while (pIn.nextPacketTag() == PacketTags_Fields.USER_ID || pIn.nextPacketTag() == PacketTags_Fields.USER_ATTRIBUTE)
			{
				Packet obj = pIn.readPacket();
				if (obj is UserIDPacket)
				{
					UserIDPacket id = (UserIDPacket)obj;
					ids.add(id);
				}
				else
				{
					UserAttributePacket user = (UserAttributePacket)obj;
					ids.add(new PGPUserAttributeSubpacketVector(user.getSubpackets()));
				}

				idTrusts.add(readOptionalTrustPacket(pIn));
				idSigs.add(readSignaturesAndTrust(pIn));
			}
		}

		/// <summary>
		/// Return the first public key in the ring.  In the case of a <seealso cref="PGPSecretKeyRing"/>
		/// this is also the public key of the master key pair.
		/// </summary>
		/// <returns> PGPPublicKey </returns>
		public abstract PGPPublicKey getPublicKey();

		/// <summary>
		/// Return an iterator containing all the public keys.
		/// </summary>
		/// <returns> Iterator </returns>
		public abstract Iterator<PGPPublicKey> getPublicKeys();

		/// <summary>
		/// Return the public key referred to by the passed in keyID if it
		/// is present.
		/// </summary>
		/// <param name="keyID"> the full keyID of the key of interest. </param>
		/// <returns> PGPPublicKey with matching keyID. </returns>
		public abstract PGPPublicKey getPublicKey(long keyID);

		/// <summary>
		/// Return the public key with the passed in fingerprint if it
		/// is present.
		/// </summary>
		/// <param name="fingerprint"> the full fingerprint of the key of interest. </param>
		/// <returns> PGPPublicKey with the matching fingerprint. </returns>
		public abstract PGPPublicKey getPublicKey(byte[] fingerprint);

		/// <summary>
		/// Return an iterator containing all the public keys carrying signatures issued from key keyID.
		/// </summary>
		/// <returns> a an iterator (possibly empty) of the public keys associated with keyID. </returns>
		public abstract Iterator<PGPPublicKey> getKeysWithSignaturesBy(long keyID);

		public abstract void encode(OutputStream outStream);

		public abstract byte[] getEncoded();

	}
}