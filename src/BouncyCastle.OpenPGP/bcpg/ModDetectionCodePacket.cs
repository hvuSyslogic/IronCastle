namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// basic packet for a modification detection code packet.
	/// </summary>
	public class ModDetectionCodePacket : ContainedPacket
	{
		private byte[] digest;

		public ModDetectionCodePacket(BCPGInputStream @in)
		{
			this.digest = new byte[20];
			@in.readFully(this.digest);
		}

		public ModDetectionCodePacket(byte[] digest)
		{
			this.digest = new byte[digest.Length];

			JavaSystem.arraycopy(digest, 0, this.digest, 0, this.digest.Length);
		}

		public virtual byte[] getDigest()
		{
			byte[] tmp = new byte[digest.Length];

			JavaSystem.arraycopy(digest, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writePacket(PacketTags_Fields.MOD_DETECTION_CODE, digest, false);
		}
	}

}