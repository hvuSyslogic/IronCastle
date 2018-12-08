/*
 * Created on Mar 6, 2004
 *
 * To change this generated comment go to 
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using MarkerPacket = org.bouncycastle.bcpg.MarkerPacket;

	/// <summary>
	/// a PGP marker packet - in general these should be ignored other than where
	/// the idea is to preserve the original input stream.
	/// </summary>
	public class PGPMarker
	{
		private MarkerPacket p;

		/// <summary>
		/// Default constructor.
		/// </summary>
		/// <param name="in"> </param>
		/// <exception cref="IOException"> </exception>
		public PGPMarker(BCPGInputStream @in)
		{
			p = (MarkerPacket)@in.readPacket();
		}
	}

}