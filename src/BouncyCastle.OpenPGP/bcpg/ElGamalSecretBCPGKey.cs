namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// base class for an ElGamal Secret Key.
	/// </summary>
	public class ElGamalSecretBCPGKey : BCPGObject, BCPGKey
	{
		internal MPInteger x;

		/// 
		/// <param name="in"> </param>
		/// <exception cref="IOException"> </exception>
		public ElGamalSecretBCPGKey(BCPGInputStream @in)
		{
			this.x = new MPInteger(@in);
		}

		/// 
		/// <param name="x"> </param>
		public ElGamalSecretBCPGKey(BigInteger x)
		{
			this.x = new MPInteger(x);
		}

		/// <summary>
		///  return "PGP"
		/// </summary>
		/// <seealso cref= org.bouncycastle.bcpg.BCPGKey#getFormat() </seealso>
		public virtual string getFormat()
		{
			return "PGP";
		}

		public virtual BigInteger getX()
		{
			return x.getValue();
		}

		/// <summary>
		/// return the standard PGP encoding of the key.
		/// </summary>
		/// <seealso cref= org.bouncycastle.bcpg.BCPGKey#getEncoded() </seealso>
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
	}

}