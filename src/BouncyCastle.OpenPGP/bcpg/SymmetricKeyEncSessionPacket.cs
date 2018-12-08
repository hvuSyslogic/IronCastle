namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// Basic type for a symmetric encrypted session key packet
	/// </summary>
	public class SymmetricKeyEncSessionPacket : ContainedPacket
	{
		private int version;
		private int encAlgorithm;
		private S2K s2k;
		private byte[] secKeyData;

		public SymmetricKeyEncSessionPacket(BCPGInputStream @in)
		{
			version = @in.read();
			encAlgorithm = @in.read();

			s2k = new S2K(@in);

			this.secKeyData = @in.readAll();
		}

		public SymmetricKeyEncSessionPacket(int encAlgorithm, S2K s2k, byte[] secKeyData)
		{
			this.version = 4;
			this.encAlgorithm = encAlgorithm;
			this.s2k = s2k;
			this.secKeyData = secKeyData;
		}

		/// <returns> int </returns>
		public virtual int getEncAlgorithm()
		{
			return encAlgorithm;
		}

		/// <returns> S2K </returns>
		public virtual S2K getS2K()
		{
			return s2k;
		}

		/// <returns> byte[] </returns>
		public virtual byte[] getSecKeyData()
		{
			return secKeyData;
		}

		/// <returns> int </returns>
		public virtual int getVersion()
		{
			return version;
		}

		public override void encode(BCPGOutputStream @out)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			BCPGOutputStream pOut = new BCPGOutputStream(bOut);

			pOut.write(version);
			pOut.write(encAlgorithm);
			pOut.writeObject(s2k);

			if (secKeyData != null && secKeyData.Length > 0)
			{
				pOut.write(secKeyData);
			}

			pOut.close();

			@out.writePacket(PacketTags_Fields.SYMMETRIC_KEY_ENC_SESSION, bOut.toByteArray(), true);
		}
	}

}