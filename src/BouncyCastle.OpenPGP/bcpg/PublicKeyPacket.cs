using System;

namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// basic packet for a PGP public key
	/// </summary>
	public class PublicKeyPacket : ContainedPacket, PublicKeyAlgorithmTags
	{
		private int version;
		private long time;
		private int validDays;
		private int algorithm;
		private BCPGKey key;

		public PublicKeyPacket(BCPGInputStream @in)
		{
			version = @in.read();
			time = ((long)@in.read() << 24) | (@in.read() << 16) | (@in.read() << 8) | @in.read();

			if (version <= 3)
			{
				validDays = (@in.read() << 8) | @in.read();
			}

			algorithm = (byte)@in.read();

			switch (algorithm)
			{
			case PublicKeyAlgorithmTags_Fields.RSA_ENCRYPT:
			case PublicKeyAlgorithmTags_Fields.RSA_GENERAL:
			case PublicKeyAlgorithmTags_Fields.RSA_SIGN:
				key = new RSAPublicBCPGKey(@in);
				break;
			case PublicKeyAlgorithmTags_Fields.DSA:
				key = new DSAPublicBCPGKey(@in);
				break;
			case PublicKeyAlgorithmTags_Fields.ELGAMAL_ENCRYPT:
			case PublicKeyAlgorithmTags_Fields.ELGAMAL_GENERAL:
				key = new ElGamalPublicBCPGKey(@in);
				break;
			case PublicKeyAlgorithmTags_Fields.ECDH:
				key = new ECDHPublicBCPGKey(@in);
				break;
			case PublicKeyAlgorithmTags_Fields.ECDSA:
				key = new ECDSAPublicBCPGKey(@in);
				break;
			case PublicKeyAlgorithmTags_Fields.EDDSA:
				key = new EdDSAPublicBCPGKey(@in);
				break;
			default:
				throw new IOException("unknown PGP public key algorithm encountered: " + algorithm);
			}
		}

		/// <summary>
		/// Construct version 4 public key packet.
		/// </summary>
		/// <param name="algorithm"> </param>
		/// <param name="time"> </param>
		/// <param name="key"> </param>
		public PublicKeyPacket(int algorithm, DateTime time, BCPGKey key)
		{
			this.version = 4;
			this.time = time.Ticks / 1000;
			this.algorithm = algorithm;
			this.key = key;
		}

		public virtual int getVersion()
		{
			return version;
		}

		public virtual int getAlgorithm()
		{
			return algorithm;
		}

		public virtual int getValidDays()
		{
			return validDays;
		}

		public virtual DateTime getTime()
		{
			return new DateTime(time * 1000);
		}

		public virtual BCPGKey getKey()
		{
			return key;
		}

		public virtual byte[] getEncodedContents()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			BCPGOutputStream pOut = new BCPGOutputStream(bOut);

			pOut.write(version);

			pOut.write((byte)(time >> 24));
			pOut.write((byte)(time >> 16));
			pOut.write((byte)(time >> 8));
			pOut.write((byte)time);

			if (version <= 3)
			{
				pOut.write((byte)(validDays >> 8));
				pOut.write((byte)validDays);
			}

			pOut.write(algorithm);

			pOut.writeObject((BCPGObject)key);

			pOut.close();

			return bOut.toByteArray();
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writePacket(PacketTags_Fields.PUBLIC_KEY, getEncodedContents(), true);
		}
	}

}