namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// base class for an ElGamal Public Key.
	/// </summary>
	public class ElGamalPublicBCPGKey : BCPGObject, BCPGKey
	{
		internal MPInteger p;
		internal MPInteger g;
		internal MPInteger y;

		/// 
		public ElGamalPublicBCPGKey(BCPGInputStream @in)
		{
			this.p = new MPInteger(@in);
			this.g = new MPInteger(@in);
			this.y = new MPInteger(@in);
		}

		public ElGamalPublicBCPGKey(BigInteger p, BigInteger g, BigInteger y)
		{
			this.p = new MPInteger(p);
			this.g = new MPInteger(g);
			this.y = new MPInteger(y);
		}

		/// <summary>
		///  return "PGP"
		/// </summary>
		/// <seealso cref= org.bouncycastle.bcpg.BCPGKey#getFormat() </seealso>
		public virtual string getFormat()
		{
			return "PGP";
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

		public virtual BigInteger getP()
		{
			return p.getValue();
		}

		public virtual BigInteger getG()
		{
			return g.getValue();
		}

		public virtual BigInteger getY()
		{
			return y.getValue();
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writeObject(p);
			@out.writeObject(g);
			@out.writeObject(y);
		}
	}

}