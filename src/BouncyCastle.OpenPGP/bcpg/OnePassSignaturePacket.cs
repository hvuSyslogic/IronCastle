namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// generic signature object
	/// </summary>
	public class OnePassSignaturePacket : ContainedPacket
	{
		private int version;
		private int sigType;
		private int hashAlgorithm;
		private int keyAlgorithm;
		private long keyID;
		private int nested;

		public OnePassSignaturePacket(BCPGInputStream @in)
		{
			version = @in.read();
			sigType = @in.read();
			hashAlgorithm = @in.read();
			keyAlgorithm = @in.read();

			keyID |= (long)@in.read() << 56;
			keyID |= (long)@in.read() << 48;
			keyID |= (long)@in.read() << 40;
			keyID |= (long)@in.read() << 32;
			keyID |= (long)@in.read() << 24;
			keyID |= (long)@in.read() << 16;
			keyID |= (long)@in.read() << 8;
			keyID |= @in.read();

			nested = @in.read();
		}

		public OnePassSignaturePacket(int sigType, int hashAlgorithm, int keyAlgorithm, long keyID, bool isNested)
		{
			this.version = 3;
			this.sigType = sigType;
			this.hashAlgorithm = hashAlgorithm;
			this.keyAlgorithm = keyAlgorithm;
			this.keyID = keyID;
			this.nested = (isNested) ? 0 : 1;
		}

		/// <summary>
		/// Return the signature type. </summary>
		/// <returns> the signature type </returns>
		public virtual int getSignatureType()
		{
			return sigType;
		}

		/// <summary>
		/// return the encryption algorithm tag
		/// </summary>
		public virtual int getKeyAlgorithm()
		{
			return keyAlgorithm;
		}

		/// <summary>
		/// return the hashAlgorithm tag
		/// </summary>
		public virtual int getHashAlgorithm()
		{
			return hashAlgorithm;
		}

		/// <returns> long </returns>
		public virtual long getKeyID()
		{
			return keyID;
		}

		/// 
		public override void encode(BCPGOutputStream @out)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			BCPGOutputStream pOut = new BCPGOutputStream(bOut);

			pOut.write(version);
			pOut.write(sigType);
			pOut.write(hashAlgorithm);
			pOut.write(keyAlgorithm);

			pOut.write((byte)(keyID >> 56));
			pOut.write((byte)(keyID >> 48));
			pOut.write((byte)(keyID >> 40));
			pOut.write((byte)(keyID >> 32));
			pOut.write((byte)(keyID >> 24));
			pOut.write((byte)(keyID >> 16));
			pOut.write((byte)(keyID >> 8));
			pOut.write((byte)(keyID));

			pOut.write(nested);

			pOut.close();

			@out.writePacket(PacketTags_Fields.ONE_PASS_SIGNATURE, bOut.toByteArray(), true);
		}
	}

}