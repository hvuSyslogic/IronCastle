using System;

namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// basic packet for a PGP public key
	/// </summary>
	public class PublicSubkeyPacket : PublicKeyPacket
	{
		public PublicSubkeyPacket(BCPGInputStream @in) : base(@in)
		{
		}

		/// <summary>
		/// Construct version 4 public key packet.
		/// </summary>
		/// <param name="algorithm"> </param>
		/// <param name="time"> </param>
		/// <param name="key"> </param>
		public PublicSubkeyPacket(int algorithm, DateTime time, BCPGKey key) : base(algorithm, time, key)
		{
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writePacket(PacketTags_Fields.PUBLIC_SUBKEY, getEncodedContents(), true);
		}
	}

}