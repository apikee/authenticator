export const cookieParser = (input: string) => {
  return input
    .split(";")
    .map((v) => v.split("="))
    .reduce((acc: Record<string, any>, v: any) => {
      acc[decodeURIComponent(v[0].trim())] = decodeURIComponent(v[1].trim());
      return acc;
    }, {});
};
