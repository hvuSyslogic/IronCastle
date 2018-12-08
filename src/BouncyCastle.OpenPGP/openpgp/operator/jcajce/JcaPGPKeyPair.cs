using System;

namespace org.bouncycastle.openpgp.@operator.jcajce
{


	/// <summary>
	/// A PGP key pair class that is constructed from JCA/JCE key pairs.
	/// </summary>
	public class JcaPGPKeyPair : PGPKeyPair
	{
		private static PGPPublicKey getPublicKey(int algorithm, PublicKey pubKey, DateTime date)
		{
			return (new JcaPGPKeyConverter()).getPGPPublicKey(algorithm, pubKey, date);
		}

		private static PGPPublicKey getPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey, DateTime date)
		{
			return (new JcaPGPKeyConverter()).getPGPPublicKey(algorithm, algorithmParameters, pubKey, date);
		}

		private static PGPPrivateKey getPrivateKey(PGPPublicKey pub, PrivateKey privKey)
		{
			return (new JcaPGPKeyConverter()).getPGPPrivateKey(pub, privKey);
		}

		/// <summary>
		/// Construct PGP key pair from a JCA/JCE key pair.
		/// </summary>
		/// <param name="algorithm"> the PGP algorithm the key is for. </param>
		/// <param name="keyPair">  the public/private key pair to convert. </param>
		/// <param name="date"> the creation date to associate with the key pair. </param>
		/// <exception cref="PGPException"> if conversion fails. </exception>
		public JcaPGPKeyPair(int algorithm, KeyPair keyPair, DateTime date)
		{
			this.pub = getPublicKey(algorithm, keyPair.getPublic(), date);
			this.priv = getPrivateKey(this.pub, keyPair.getPrivate());
		}

		/// <summary>
		/// Construct PGP key pair from a JCA/JCE key pair.
		/// </summary>
		/// <param name="algorithm"> the PGP algorithm the key is for. </param>
		/// <param name="parameters"> additional parameters to be stored against the public key. </param>
		/// <param name="keyPair">  the public/private key pair to convert. </param>
		/// <param name="date"> the creation date to associate with the key pair. </param>
		/// <exception cref="PGPException"> if conversion fails. </exception>
		public JcaPGPKeyPair(int algorithm, PGPAlgorithmParameters parameters, KeyPair keyPair, DateTime date)
		{
			this.pub = getPublicKey(algorithm, parameters, keyPair.getPublic(), date);
			this.priv = getPrivateKey(this.pub, keyPair.getPrivate());
		}
	}

}