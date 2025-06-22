import { ReactFlow } from "@xyflow/react";
import { Fragment } from "react/jsx-runtime";
import ToggleTheme from "./components/ui/ToggleTheme";
import { useState } from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "./components/ui/card";
import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Label } from "./components/ui/label";

const initialNodes = [
  { id: "1", position: { x: 0, y: 0 }, data: { label: "1" } },
  { id: "2", position: { x: 0, y: 100 }, data: { label: "2" } },
];
const initialEdges = [{ id: "e1-2", source: "1", target: "2" }];

export default function App() {
  const [hasLoadedData, setHasLoadedData] = useState(false);

  return (
    <Fragment>
      <main className="w-screen h-screen">
        {hasLoadedData ? (
          <ReactFlow nodes={initialNodes} edges={initialEdges} />
        ) : (
          <div className="w-full h-full flex items-center justify-center px-3">
            <Card className="sm:max-w-[450px] w-full">
              <CardHeader>
                <CardTitle>Select dump file</CardTitle>
                <CardDescription>Attach the file dumped using Volvulus Twist.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col gap-2">
                  <Label>Dump file</Label>
                  <Input type="file" accept=".json" />
                </div>
              </CardContent>
              <CardFooter>
                <Button className="ml-auto">Load</Button>
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
