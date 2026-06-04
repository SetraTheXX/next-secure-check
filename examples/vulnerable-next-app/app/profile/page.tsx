export default function ProfilePage({ searchParams }: { searchParams: { preview?: string } }) {
  const profileHtml = searchParams.preview ?? "";
  return <main dangerouslySetInnerHTML={{ __html: profileHtml }} />;
}
