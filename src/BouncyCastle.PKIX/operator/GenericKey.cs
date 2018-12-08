namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class GenericKey
	{
		private AlgorithmIdentifier algorithmIdentifier;
		private object representation;

		/// @deprecated provide an AlgorithmIdentifier. 
		/// <param name="representation"> key data </param>
		public GenericKey(object representation)
		{
			this.algorithmIdentifier = null;
			this.representation = representation;
		}

		public GenericKey(AlgorithmIdentifier algorithmIdentifier, byte[] representation)
		{
			this.algorithmIdentifier = algorithmIdentifier;
			this.representation = representation;
		}

		public GenericKey(AlgorithmIdentifier algorithmIdentifier, object representation)
		{
			this.algorithmIdentifier = algorithmIdentifier;
			this.representation = representation;
		}

		public virtual AlgorithmIdentifier getAlgorithmIdentifier()
		{
			return algorithmIdentifier;
		}

		public virtual object getRepresentation()
		{
			return representation;
		}
	}

}