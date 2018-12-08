namespace org.bouncycastle.crypto.engines
{
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// Support class for constructing integrated encryption ciphers
	/// for doing basic message exchanges on top of key agreement ciphers.
	/// Follows the description given in IEEE Std 1363a.
	/// </summary>
	public class OldIESEngine : IESEngine
	{
		/// <summary>
		/// set up for use with stream mode, where the key derivation function
		/// is used to provide a stream of bytes to xor with the message.
		/// </summary>
		/// <param name="agree"> the key agreement used as the basis for the encryption </param>
		/// <param name="kdf">   the key derivation function used for byte generation </param>
		/// <param name="mac">   the message authentication code generator for the message </param>
		public OldIESEngine(BasicAgreement agree, DerivationFunction kdf, Mac mac) : base(agree, kdf, mac)
		{
		}


		/// <summary>
		/// set up for use in conjunction with a block cipher to handle the
		/// message.
		/// </summary>
		/// <param name="agree">  the key agreement used as the basis for the encryption </param>
		/// <param name="kdf">    the key derivation function used for byte generation </param>
		/// <param name="mac">    the message authentication code generator for the message </param>
		/// <param name="cipher"> the cipher to used for encrypting the message </param>
		public OldIESEngine(BasicAgreement agree, DerivationFunction kdf, Mac mac, BufferedBlockCipher cipher) : base(agree, kdf, mac, cipher)
		{
		}

		public override byte[] getLengthTag(byte[] p2)
		{
			byte[] L2 = new byte[4];
			if (p2 != null)
			{
				Pack.intToBigEndian(p2.Length * 8, L2, 0);
			}
			return L2;
		}
	}

}