namespace org.bouncycastle.crypto.@params
{

	public class AsymmetricKeyParameter : CipherParameters
	{
		internal bool privateKey;

		public AsymmetricKeyParameter(bool privateKey)
		{
			this.privateKey = privateKey;
		}

		public virtual bool isPrivate()
		{
			return privateKey;
		}
	}

}