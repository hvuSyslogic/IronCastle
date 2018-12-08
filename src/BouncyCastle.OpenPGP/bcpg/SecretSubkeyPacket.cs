namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// basic packet for a PGP secret key
	/// </summary>
	public class SecretSubkeyPacket : SecretKeyPacket
	{
		/// 
		/// <param name="in"> </param>
		/// <exception cref="IOException"> </exception>
		public SecretSubkeyPacket(BCPGInputStream @in) : base(@in)
		{
		}

		/// 
		/// <param name="pubKeyPacket"> </param>
		/// <param name="encAlgorithm"> </param>
		/// <param name="s2k"> </param>
		/// <param name="iv"> </param>
		/// <param name="secKeyData"> </param>
		public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, int encAlgorithm, S2K s2k, byte[] iv, byte[] secKeyData) : base(pubKeyPacket, encAlgorithm, s2k, iv, secKeyData)
		{
		}

		public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, int encAlgorithm, int s2kUsage, S2K s2k, byte[] iv, byte[] secKeyData) : base(pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData)
		{
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writePacket(PacketTags_Fields.SECRET_SUBKEY, getEncodedContents(), true);
		}
	}

}