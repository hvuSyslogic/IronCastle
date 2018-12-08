namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// A symmetric key encrypted packet with an associated integrity check code.
	/// </summary>
	public class SymmetricEncIntegrityPacket : InputStreamPacket
	{
		internal int version;

		public SymmetricEncIntegrityPacket(BCPGInputStream @in) : base(@in)
		{

			version = @in.read();
		}
	}

}