namespace org.bouncycastle.bcpg
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// basic packet for a PGP public key
	/// </summary>
	public class PublicKeyEncSessionPacket : ContainedPacket, PublicKeyAlgorithmTags
	{
		private int version;
		private long keyID;
		private int algorithm;
		private byte[][] data;

		public PublicKeyEncSessionPacket(BCPGInputStream @in)
		{
			version = @in.read();

			keyID |= (long)@in.read() << 56;
			keyID |= (long)@in.read() << 48;
			keyID |= (long)@in.read() << 40;
			keyID |= (long)@in.read() << 32;
			keyID |= (long)@in.read() << 24;
			keyID |= (long)@in.read() << 16;
			keyID |= (long)@in.read() << 8;
			keyID |= @in.read();

			algorithm = @in.read();

			switch (algorithm)
			{
			case PublicKeyAlgorithmTags_Fields.RSA_ENCRYPT:
			case PublicKeyAlgorithmTags_Fields.RSA_GENERAL:
				data = new byte[1][];

				data[0] = (new MPInteger(@in)).getEncoded();
				break;
			case PublicKeyAlgorithmTags_Fields.ELGAMAL_ENCRYPT:
			case PublicKeyAlgorithmTags_Fields.ELGAMAL_GENERAL:
				data = new byte[2][];

				data[0] = (new MPInteger(@in)).getEncoded();
				data[1] = (new MPInteger(@in)).getEncoded();
				break;
			case PublicKeyAlgorithmTags_Fields.ECDH:
				data = new byte[1][];

				data[0] = Streams.readAll(@in);
				break;
			default:
				throw new IOException("unknown PGP public key algorithm encountered");
			}
		}

		public PublicKeyEncSessionPacket(long keyID, int algorithm, byte[][] data)
		{
			this.version = 3;
			this.keyID = keyID;
			this.algorithm = algorithm;
			this.data = new byte[data.Length][];

			for (int i = 0; i != data.Length; i++)
			{
				this.data[i] = Arrays.clone(data[i]);
			}
		}

		public virtual int getVersion()
		{
			return version;
		}

		public virtual long getKeyID()
		{
			return keyID;
		}

		public virtual int getAlgorithm()
		{
			return algorithm;
		}

		public virtual byte[][] getEncSessionKey()
		{
			return data;
		}

		public override void encode(BCPGOutputStream @out)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			BCPGOutputStream pOut = new BCPGOutputStream(bOut);

			  pOut.write(version);

			pOut.write((byte)(keyID >> 56));
			pOut.write((byte)(keyID >> 48));
			pOut.write((byte)(keyID >> 40));
			pOut.write((byte)(keyID >> 32));
			pOut.write((byte)(keyID >> 24));
			pOut.write((byte)(keyID >> 16));
			pOut.write((byte)(keyID >> 8));
			pOut.write((byte)(keyID));

			pOut.write(algorithm);

			for (int i = 0; i != data.Length; i++)
			{
				pOut.write(data[i]);
			}

			pOut.close();

			@out.writePacket(PacketTags_Fields.PUBLIC_KEY_ENC_SESSION, bOut.toByteArray(), true);
		}
	}

}