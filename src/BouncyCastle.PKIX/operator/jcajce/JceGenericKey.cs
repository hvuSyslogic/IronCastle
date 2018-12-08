namespace org.bouncycastle.@operator.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class JceGenericKey : GenericKey
	{
		/// <summary>
		/// Attempt to simplify the key representation if possible.
		/// </summary>
		/// <param name="key"> a provider based key </param>
		/// <returns> the byte encoding if one exists, key object otherwise. </returns>
		private static object getRepresentation(Key key)
		{
			byte[] keyBytes = key.getEncoded();

			if (keyBytes != null)
			{
				return keyBytes;
			}

			return key;
		}

		public JceGenericKey(AlgorithmIdentifier algorithmIdentifier, Key representation) : base(algorithmIdentifier, getRepresentation(representation))
		{
		}
	}

}