namespace org.bouncycastle.openpgp.@operator
{

	using ContainedPacket = org.bouncycastle.bcpg.ContainedPacket;
	using MPInteger = org.bouncycastle.bcpg.MPInteger;
	using PublicKeyEncSessionPacket = org.bouncycastle.bcpg.PublicKeyEncSessionPacket;

	public abstract class PublicKeyKeyEncryptionMethodGenerator : PGPKeyEncryptionMethodGenerator
	{
		private PGPPublicKey pubKey;

		public PublicKeyKeyEncryptionMethodGenerator(PGPPublicKey pubKey)
		{
			this.pubKey = pubKey;

			switch (pubKey.getAlgorithm())
			{
			case PGPPublicKey.RSA_ENCRYPT:
			case PGPPublicKey.RSA_GENERAL:
				break;
			case PGPPublicKey.RSA_SIGN:
				throw new IllegalArgumentException("Can't use an RSA_SIGN key for encryption.");
			case PGPPublicKey.ELGAMAL_ENCRYPT:
			case PGPPublicKey.ELGAMAL_GENERAL:
				break;
			case PGPPublicKey.ECDH:
				break;
			case PGPPublicKey.DSA:
				throw new IllegalArgumentException("Can't use DSA for encryption.");
			case PGPPublicKey.ECDSA:
				throw new IllegalArgumentException("Can't use ECDSA for encryption.");
			default:
				throw new IllegalArgumentException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
			}
		}

		public virtual byte[][] processSessionInfo(byte[] encryptedSessionInfo)
		{
			byte[][] data;

			switch (pubKey.getAlgorithm())
			{
			case PGPPublicKey.RSA_ENCRYPT:
			case PGPPublicKey.RSA_GENERAL:
				data = new byte[1][];

				data[0] = convertToEncodedMPI(encryptedSessionInfo);
				break;
			case PGPPublicKey.ELGAMAL_ENCRYPT:
			case PGPPublicKey.ELGAMAL_GENERAL:
				byte[] b1 = new byte[encryptedSessionInfo.Length / 2];
				byte[] b2 = new byte[encryptedSessionInfo.Length / 2];

				JavaSystem.arraycopy(encryptedSessionInfo, 0, b1, 0, b1.Length);
				JavaSystem.arraycopy(encryptedSessionInfo, b1.Length, b2, 0, b2.Length);

				data = new byte[2][];
				data[0] = convertToEncodedMPI(b1);
				data[1] = convertToEncodedMPI(b2);
				break;
			case PGPPublicKey.ECDH:
				data = new byte[1][];

				data[0] = encryptedSessionInfo;
				break;
			default:
				throw new PGPException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
			}

			return data;
		}

		private byte[] convertToEncodedMPI(byte[] encryptedSessionInfo)
		{
			try
			{
				return (new MPInteger(new BigInteger(1, encryptedSessionInfo))).getEncoded();
			}
			catch (IOException e)
			{
				throw new PGPException("Invalid MPI encoding: " + e.Message, e);
			}
		}

		public override ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
		{
			return new PublicKeyEncSessionPacket(pubKey.getKeyID(), pubKey.getAlgorithm(), processSessionInfo(encryptSessionInfo(pubKey, sessionInfo)));
		}

		public abstract byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo);
	}

}