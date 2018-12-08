namespace org.bouncycastle.kmip.wire
{
	public interface KMIPItem<T> : KMIPEncodable
	{
		int getTag();

		byte getType();

		long getLength();

		T getValue();
	}

}