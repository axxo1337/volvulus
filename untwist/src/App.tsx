/* eslint-disable @typescript-eslint/no-explicit-any */
import { ReactFlow } from "@xyflow/react";
import { Fragment } from "react/jsx-runtime";
import ToggleTheme from "./components/ui/ToggleTheme";
import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "./components/ui/card";
import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Label } from "./components/ui/label";
import { Loader2 } from "lucide-react";

const initialNodes = [
  { id: "1", position: { x: 0, y: 0 }, data: { label: "1" } },
  { id: "2", position: { x: 0, y: 100 }, data: { label: "2" } },
];
const initialEdges = [{ id: "e1-2", source: "1", target: "2" }];

export default function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dataState, setDataState] = useState({
    loaded: false,
    processed: false,
  });

  const handleSelectFile = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] || null;
    setSelectedFile(file);
    setError(null);
  };

  const handleLoadFile = async () => {
    if (!selectedFile) return;

    try {
      const fileContent = await selectedFile.text();
      const parsedData = JSON.parse(fileContent);

      console.log("Loaded data:", parsedData);
      setDataState({ loaded: true, processed: false });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to parse JSON file";
      setError(errorMessage);
    }
  };

  useEffect(() => {
    if (dataState.loaded && !dataState.processed) {
      console.log("TEST");
    }
  }, [dataState]);

  return (
    <Fragment>
      <main className="w-screen h-screen">
        {error ? (
          <span className="text-red-500 text-lg absolute text-center max-w-[400px] left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
            {error}
          </span>
        ) : dataState.loaded ? (
          dataState.processed ? (
            <ReactFlow nodes={initialNodes} edges={initialEdges} />
          ) : (
            <Loader2 size={32} className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 animate-spin" />
          )
        ) : (
          <div className="w-full h-full flex items-center justify-center px-3">
            <Card className="sm:max-w-[450px] w-full">
              <CardHeader>
                <CardTitle>Select dump file</CardTitle>
                <CardDescription>Attach the file dumped using Volvulus Twist.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col gap-2">
                  <Label htmlFor="dump-file">Dump file</Label>
                  <Input id="dump-file" onChange={handleSelectFile} type="file" accept=".json" />
                </div>
              </CardContent>
              <CardFooter>
                <Button className="ml-auto" onClick={handleLoadFile} disabled={!selectedFile}>
                  Load
                </Button>
              </CardFooter>
            </Card>
          </div>
        )}
      </main>
      <div className="fixed bottom-3 right-3">
        <ToggleTheme />
      </div>
    </Fragment>
  );
}
