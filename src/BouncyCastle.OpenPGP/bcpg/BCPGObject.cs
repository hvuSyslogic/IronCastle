namespace org.bouncycastle.bcpg
{

	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// Base class for a PGP object.
	/// </summary>
	public abstract class BCPGObject : Encodable
	{
		public virtual byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			BCPGOutputStream pOut = new BCPGOutputStream(bOut);

			pOut.writeObject(this);

			pOut.close();

			return bOut.toByteArray();
		}

		public abstract void encode(BCPGOutputStream @out);
	}

}