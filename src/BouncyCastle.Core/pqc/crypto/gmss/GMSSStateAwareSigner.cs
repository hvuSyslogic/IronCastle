using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.gmss
{
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using Memoable = org.bouncycastle.util.Memoable;

	/// <summary>
	/// This class implements the GMSS signature scheme, but allows multiple signatures to be generated.
	/// <para>
	///     Note:  getUpdatedPrivateKey() needs to be called to fetch the current value of the usable private key.
	/// </para>
	/// </summary>
	public class GMSSStateAwareSigner : StateAwareMessageSigner
	{
		private readonly GMSSSigner gmssSigner;

		private GMSSPrivateKeyParameters key;


		public GMSSStateAwareSigner(Digest digest)
		{
			if (!(digest is Memoable))
			{
				throw new IllegalArgumentException("digest must implement Memoable");
			}


			Memoable dig = ((Memoable)digest).copy();
			gmssSigner = new GMSSSigner(new GMSSDigestProviderAnonymousInnerClass(this, dig));
		}

		public class GMSSDigestProviderAnonymousInnerClass : GMSSDigestProvider
		{
			private readonly GMSSStateAwareSigner outerInstance;

			private Memoable dig;

			public GMSSDigestProviderAnonymousInnerClass(GMSSStateAwareSigner outerInstance, Memoable dig)
			{
				this.outerInstance = outerInstance;
				this.dig = dig;
			}

			public Digest get()
			{
				return (Digest)dig.copy();
			}
		}

		public virtual void init(bool forSigning, CipherParameters param)
		{
			if (forSigning)
			{
				if (param is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)param;

					this.key = (GMSSPrivateKeyParameters)rParam.getParameters();
				}
				else
				{
					this.key = (GMSSPrivateKeyParameters)param;
				}
			}

			gmssSigner.init(forSigning, param);
		}

		public virtual byte[] generateSignature(byte[] message)
		{
			if (key == null)
			{
				throw new IllegalStateException("signing key no longer usable");
			}

			byte[] sig = gmssSigner.generateSignature(message);

			key = key.nextKey();

			return sig;
		}

		public virtual bool verifySignature(byte[] message, byte[] signature)
		{
			return gmssSigner.verifySignature(message, signature);
		}

		public virtual AsymmetricKeyParameter getUpdatedPrivateKey()
		{
			AsymmetricKeyParameter k = key;

			key = null;

			return k;
		}
	}
}