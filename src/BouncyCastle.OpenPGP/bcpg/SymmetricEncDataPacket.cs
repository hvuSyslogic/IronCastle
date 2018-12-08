namespace org.bouncycastle.bcpg
{
	/// <summary>
	/// Basic type for a symmetric key encrypted packet
	/// </summary>
	public class SymmetricEncDataPacket : InputStreamPacket
	{
		public SymmetricEncDataPacket(BCPGInputStream @in) : base(@in)
		{
		}
	}

}