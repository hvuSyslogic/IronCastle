namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// base class for an Edwards Curve Secret Key.
	/// </summary>
	public class EdSecretBCPGKey : BCPGObject, BCPGKey
	{
		internal MPInteger x;

		/// <param name="in"> </param>
		/// <exception cref="IOException"> </exception>
		public EdSecretBCPGKey(BCPGInputStream @in)
		{
			this.x = new MPInteger(@in);
		}

		/// <param name="x"> </param>
		public EdSecretBCPGKey(BigInteger x)
		{
			this.x = new MPInteger(x);
		}

		/// <summary>
		/// return "PGP"
		/// </summary>
		/// <seealso cref= BCPGKey#getFormat() </seealso>
		public virtual string getFormat()
		{
			return "PGP";
		}

		/// <summary>
		/// return the standard PGP encoding of the key.
		/// </summary>
		/// <seealso cref= BCPGKey#getEncoded() </seealso>
		public override byte[] getEncoded()
		{
			try
			{
				return base.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writeObject(x);
		}

		/// <returns> x </returns>
		public virtual BigInteger getX()
		{
			return x.getValue();
		}
	}

}