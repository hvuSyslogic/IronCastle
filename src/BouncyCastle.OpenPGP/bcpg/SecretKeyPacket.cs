namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// basic packet for a PGP secret key
	/// </summary>
	public class SecretKeyPacket : ContainedPacket, PublicKeyAlgorithmTags
	{
		public const int USAGE_NONE = 0x00;
		public const int USAGE_CHECKSUM = 0xff;
		public const int USAGE_SHA1 = 0xfe;

		private PublicKeyPacket pubKeyPacket;
		private byte[] secKeyData;
		private int s2kUsage;
		private int encAlgorithm;
		private S2K s2k;
		private byte[] iv;

		/// 
		/// <param name="in"> </param>
		/// <exception cref="IOException"> </exception>
		public SecretKeyPacket(BCPGInputStream @in)
		{
			if (this is SecretSubkeyPacket)
			{
				pubKeyPacket = new PublicSubkeyPacket(@in);
			}
			else
			{
				pubKeyPacket = new PublicKeyPacket(@in);
			}

			s2kUsage = @in.read();

			if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1)
			{
				encAlgorithm = @in.read();
				s2k = new S2K(@in);
			}
			else
			{
				encAlgorithm = s2kUsage;
			}

			if (!(s2k != null && s2k.getType() == S2K.GNU_DUMMY_S2K && s2k.getProtectionMode() == 0x01))
			{
				if (s2kUsage != 0)
				{
					if (encAlgorithm < 7)
					{
						iv = new byte[8];
					}
					else
					{
						iv = new byte[16];
					}
					@in.readFully(iv, 0, iv.Length);
				}
			}

			this.secKeyData = @in.readAll();
		}

		/// 
		/// <param name="pubKeyPacket"> </param>
		/// <param name="encAlgorithm"> </param>
		/// <param name="s2k"> </param>
		/// <param name="iv"> </param>
		/// <param name="secKeyData"> </param>
		public SecretKeyPacket(PublicKeyPacket pubKeyPacket, int encAlgorithm, S2K s2k, byte[] iv, byte[] secKeyData)
		{
			this.pubKeyPacket = pubKeyPacket;
			this.encAlgorithm = encAlgorithm;

			if (encAlgorithm != SymmetricKeyAlgorithmTags_Fields.NULL)
			{
				this.s2kUsage = USAGE_CHECKSUM;
			}
			else
			{
				this.s2kUsage = USAGE_NONE;
			}

			this.s2k = s2k;
			this.iv = iv;
			this.secKeyData = secKeyData;
		}

		public SecretKeyPacket(PublicKeyPacket pubKeyPacket, int encAlgorithm, int s2kUsage, S2K s2k, byte[] iv, byte[] secKeyData)
		{
			this.pubKeyPacket = pubKeyPacket;
			this.encAlgorithm = encAlgorithm;
			this.s2kUsage = s2kUsage;
			this.s2k = s2k;
			this.iv = iv;
			this.secKeyData = secKeyData;
		}

		public virtual int getEncAlgorithm()
		{
			return encAlgorithm;
		}

		public virtual int getS2KUsage()
		{
			return s2kUsage;
		}

		public virtual byte[] getIV()
		{
			return iv;
		}

		public virtual S2K getS2K()
		{
			return s2k;
		}

		public virtual PublicKeyPacket getPublicKeyPacket()
		{
			return pubKeyPacket;
		}

		public virtual byte[] getSecretKeyData()
		{
			return secKeyData;
		}

		public virtual byte[] getEncodedContents()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			BCPGOutputStream pOut = new BCPGOutputStream(bOut);

			pOut.write(pubKeyPacket.getEncodedContents());

			pOut.write(s2kUsage);

			if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1)
			{
				pOut.write(encAlgorithm);
				pOut.writeObject(s2k);
			}

			if (iv != null)
			{
				pOut.write(iv);
			}

			if (secKeyData != null && secKeyData.Length > 0)
			{
				pOut.write(secKeyData);
			}

			pOut.close();

			return bOut.toByteArray();
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writePacket(PacketTags_Fields.SECRET_KEY, getEncodedContents(), true);
		}
	}

}