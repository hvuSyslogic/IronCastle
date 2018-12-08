namespace org.bouncycastle.kmip.wire
{

	public interface KMIPEncoder
	{
		void output(KMIPEncodable item);
	}

}